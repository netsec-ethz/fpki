package logserver

// this file is copied from the trillian github, and I made some midifications on it.
// Modification: instead of insert the paras as flag, I init the server using config file.

import (
	"context"
	_ "net/http/pprof" // Register pprof HTTP handlers.
	"os"
	"time"

	"github.com/golang/glog"
	"github.com/google/trillian"
	"github.com/google/trillian/extension"
	"github.com/google/trillian/monitoring"
	"github.com/google/trillian/monitoring/opencensus"
	"github.com/google/trillian/quota"
	"github.com/google/trillian/server"
	"github.com/google/trillian/storage"
	"github.com/google/trillian/util"
	"github.com/google/trillian/util/clock"
	serverUtil "github.com/netsec-ethz/fpki/pkg/policylog/server/util"
	"google.golang.org/grpc"

	// Register supported storage providers.
	_ "github.com/google/trillian/storage/cloudspanner"
	_ "github.com/google/trillian/storage/mysql"

	// Load MySQL quota provider
	"flag"

	_ "github.com/google/trillian/quota/mysqlqm"
)

// TODO(juagargi) this file is too complex really for what we need. Rethink it.

// LogServer: struc for a log server
type LogServer struct {
	config *LogServerConfig
}

// PLCreateLogServer: Create a log server
func PLCreateLogServer(configPath string) {
	flag.Parse()

	logConfig := &LogServerConfig{}
	pl_LogServer := &LogServer{
		config: logConfig,
	}

	err := ReadLogConfigFromFile(logConfig, configPath)
	if err != nil {
		glog.Exitf("Failed to read config file: %v", err)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go util.AwaitSignal(ctx, cancel)

	monitoring.SetStartSpan(opencensus.StartSpan)

	sp, err := storage.NewProvider(pl_LogServer.config.StorageSystem, nil)
	if err != nil {
		glog.Exitf("Failed to get storage provider: %v", err)
	}
	defer sp.Close()

	qm, err := quota.NewManager(pl_LogServer.config.QuotaSystem)
	if err != nil {
		glog.Exitf("Error creating quota manager: %v", err)
	}

	registry := extension.Registry{
		AdminStorage:  sp.AdminStorage(),
		LogStorage:    sp.LogStorage(),
		QuotaManager:  qm,
		MetricFactory: nil,
	}

	m := serverUtil.Main{
		RPCEndpoint:  pl_LogServer.config.RpcEndpoint,
		HTTPEndpoint: pl_LogServer.config.HttpEndpoint,
		TLSCertFile:  "",
		TLSKeyFile:   "",
		StatsPrefix:  "log",
		ExtraOptions: []grpc.ServerOption{},
		QuotaDryRun:  false,
		DBClose:      sp.Close,
		Registry:     registry,
		RegisterServerFn: func(s *grpc.Server, registry extension.Registry) error {
			logServer := server.NewTrillianLogRPCServer(registry, clock.System)
			if err := logServer.IsHealthy(); err != nil {
				return err
			}
			trillian.RegisterTrillianLogServer(s, logServer)
			return nil
		},
		IsHealthy: func(ctx context.Context) error {
			as := sp.AdminStorage()
			return as.CheckDatabaseAccessible(ctx)
		},
		HealthyDeadline:       time.Second * time.Duration(pl_LogServer.config.HealthzTimeout),
		AllowedTreeTypes:      []trillian.TreeType{trillian.TreeType_LOG, trillian.TreeType_PREORDERED_LOG},
		TreeGCEnabled:         pl_LogServer.config.TreeGCEnabled,
		TreeDeleteThreshold:   time.Hour * time.Duration(pl_LogServer.config.TreeDeleteThresholdInHour),
		TreeDeleteMinInterval: time.Hour * time.Duration(pl_LogServer.config.TreeDeleteMinRunIntervalInHour),
	}

	if err := m.Run(ctx); err != nil {
		glog.Exitf("Server exited with error: %v", err)
	}
}

func mustCreate(fileName string) *os.File {
	f, err := os.Create(fileName)
	if err != nil {
		glog.Fatal(err)
	}
	return f
}
