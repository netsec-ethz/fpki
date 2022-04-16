package PL_logSigner

import (
	"context"
	"flag"
	"fmt"
	_ "net/http/pprof" // Register pprof HTTP handlers.
	"os"
	"runtime/pprof"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/google/trillian/extension"
	"github.com/google/trillian/log"
	"github.com/google/trillian/monitoring"
	"github.com/google/trillian/monitoring/opencensus"
	"github.com/google/trillian/monitoring/prometheus"
	"github.com/google/trillian/quota"
	"github.com/google/trillian/quota/etcd"
	"github.com/google/trillian/storage"
	"github.com/google/trillian/util"
	"github.com/google/trillian/util/clock"
	"github.com/google/trillian/util/election"
	"github.com/google/trillian/util/election2"
	etcdelect "github.com/google/trillian/util/election2/etcd"
	clientv3 "go.etcd.io/etcd/client/v3"
	"google.golang.org/grpc"

	// Register supported storage providers.
	_ "github.com/google/trillian/storage/cloudspanner"
	_ "github.com/google/trillian/storage/mysql"

	// Load MySQL quota provider
	_ "github.com/google/trillian/quota/mysqlqm"
)

type PL_LogSigner struct {
	config *PL_LogSignerConfig
}

func PL_CreateLogSigner(configPath string) {
	flag.Parse()

	logConfig := &PL_LogSignerConfig{}
	pl_LogServer := &PL_LogSigner{
		config: logConfig,
	}

	err := PL_ReadLogSignerConfigFromFile(logConfig, configPath)
	if err != nil {
		glog.Exitf("Failed to read config file: %v", err)
		return
	}

	glog.CopyStandardLogTo("WARNING")
	glog.Info("**** Log Signer Starting ****")

	mf := prometheus.MetricFactory{}
	monitoring.SetStartSpan(opencensus.StartSpan)

	sp, err := storage.NewProvider(pl_LogServer.config.StorageSystem, mf)
	if err != nil {
		glog.Exitf("Failed to get storage provider: %v", err)
	}
	defer sp.Close()

	var client *clientv3.Client
	if servers := *etcd.Servers; servers != "" {
		if client, err = clientv3.New(clientv3.Config{
			Endpoints:   strings.Split(servers, ","),
			DialTimeout: 5 * time.Second,
		}); err != nil {
			glog.Exitf("Failed to connect to etcd at %v: %v", servers, err)
		}
		defer client.Close()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go util.AwaitSignal(ctx, cancel)

	hostname, _ := os.Hostname()
	instanceID := fmt.Sprintf("%s.%d", hostname, os.Getpid())
	var electionFactory election2.Factory
	switch {
	case pl_LogServer.config.ForceMaster:
		glog.Warning("**** Acting as master for all logs ****")
		electionFactory = election2.NoopFactory{}
	case client != nil:
		electionFactory = etcdelect.NewFactory(instanceID, client, pl_LogServer.config.LockDir)
	default:
		glog.Exit("Either --force_master or --etcd_servers must be supplied")
	}

	qm, err := quota.NewManager(pl_LogServer.config.QuotaSystem)
	if err != nil {
		glog.Exitf("Error creating quota manager: %v", err)
	}

	registry := extension.Registry{
		AdminStorage:    sp.AdminStorage(),
		LogStorage:      sp.LogStorage(),
		ElectionFactory: electionFactory,
		QuotaManager:    qm,
		MetricFactory:   mf,
	}

	// Start HTTP server (optional)
	if pl_LogServer.config.HttpEndpoint != "" {
		// Announce our endpoint to etcd if so configured.
		unannounceHTTP := AnnounceSelf(ctx, client, pl_LogServer.config.EtcdHTTPService, pl_LogServer.config.HttpEndpoint, cancel)
		defer unannounceHTTP()
	}

	// Start the sequencing loop, which will run until we terminate the process. This controls
	// both sequencing and signing.
	// TODO(Martin2112): Should respect read only mode and the flags in tree control etc
	log.QuotaIncreaseFactor = pl_LogServer.config.QuotaIncreaseFactor
	sequencerManager := log.NewSequencerManager(registry, time.Second*time.Duration(pl_LogServer.config.SequencerGuardWindowFlagInSec))
	info := log.OperationInfo{
		Registry:    registry,
		BatchSize:   pl_LogServer.config.BatchSizeFlag,
		NumWorkers:  pl_LogServer.config.NumSeqFlag,
		RunInterval: time.Millisecond * time.Duration(pl_LogServer.config.SequencerIntervalFlagInMillSec),
		TimeSource:  clock.System,
		ElectionConfig: election.RunnerConfig{
			PreElectionPause:   time.Second * time.Duration(pl_LogServer.config.PreElectionPauseInSec),
			MasterHoldInterval: time.Second * time.Duration(pl_LogServer.config.MasterHoldIntervalInSec),
			MasterHoldJitter:   time.Second * time.Duration(pl_LogServer.config.MasterHoldJitterInSec),
			TimeSource:         clock.System,
		},
	}
	sequencerTask := log.NewOperationManager(info, sequencerManager)
	go sequencerTask.OperationLoop(ctx)

	// Enable CPU profile if requested
	if pl_LogServer.config.CpuProfile != "" {
		f := mustCreate(pl_LogServer.config.CpuProfile)
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	m := Main{
		RPCEndpoint:      pl_LogServer.config.RpcEndpoint,
		HTTPEndpoint:     pl_LogServer.config.HttpEndpoint,
		TLSCertFile:      pl_LogServer.config.TlsCertFile,
		TLSKeyFile:       pl_LogServer.config.TlsKeyFile,
		StatsPrefix:      "logsigner",
		DBClose:          sp.Close,
		Registry:         registry,
		RegisterServerFn: func(s *grpc.Server, _ extension.Registry) error { return nil },
		IsHealthy:        sp.AdminStorage().CheckDatabaseAccessible,
		HealthyDeadline:  time.Second * time.Duration(pl_LogServer.config.HealthzTimeoutInSec),
	}

	if err := m.Run(ctx); err != nil {
		glog.Exitf("Server exited with error: %v", err)
	}

	if pl_LogServer.config.MemProfile != "" {
		f := mustCreate(pl_LogServer.config.MemProfile)
		pprof.WriteHeapProfile(f)
	}

	// Give things a few seconds to tidy up
	glog.Infof("Stopping server, about to exit")
	time.Sleep(time.Second * 5)
}

func mustCreate(fileName string) *os.File {
	f, err := os.Create(fileName)
	if err != nil {
		glog.Fatal(err)
	}
	return f
}
