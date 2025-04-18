package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"flag"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/db/mysql"
	"github.com/netsec-ethz/fpki/pkg/mapserver"
	"github.com/netsec-ethz/fpki/pkg/mapserver/config"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	"github.com/netsec-ethz/fpki/pkg/util"
)

const VERSION = "0.2.1"

const waitForExitBeforePanicTime = 10 * time.Second

func main() {
	os.Exit(mainFunc())
}

func mainFunc() int {
	// Because some packages (glog) change the flags to main, and we don't want/need them, reset
	// the flags before touching them.
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	// Prepare our flags.
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage:\n%s configuration_file\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.CommandLine.Usage = flag.Usage

	var showVersion bool
	flag.BoolVar(&showVersion, "version", false, "Print map server version")
	flag.BoolVar(&showVersion, "v", false, "Print map server version")
	updateVar := flag.Bool("updateNow", false, "Immediately trigger an update cycle")
	createSampleConfig := flag.Bool("createSampleConfig", false,
		"Create configuration file specified by positional argument")
	insertPolicyVar := flag.String("policyFile", "", "policy certificate file to be ingested into the mapserver")
	flag.Parse()

	if showVersion {
		fmt.Printf("FP-PKI Map Server %s\n", VERSION)
		return 0
	}

	// We need the configuration file as the first positional argument.
	if flag.NArg() != 1 {
		flag.Usage()
		return 1
	}

	var err error
	switch {
	case *createSampleConfig:
		err = writeSampleConfig()
	case *insertPolicyVar != "":
		err = insertPolicyFromFile(*insertPolicyVar)
	default:
		err = run(*updateVar)
	}

	// We have finished. Probably the context created in run was been cancelled (exit request).
	// Print message in case of error.
	return manageError(err)
}

func insertPolicyFromFile(policyFile string) error {
	fmt.Printf("inserting policy from %s\n", policyFile)

	ctx := context.Background()
	// Load configuration and insert policy with it.
	conf, err := config.ReadConfigFromFile(flag.Arg(0))
	if err != nil {
		return err
	}
	server, err := mapserver.NewMapServer(ctx, conf)
	if err != nil {
		return err
	}
	root, err := server.Conn.LoadRoot(ctx)
	if err != nil {
		return err
	}

	pc, err := util.PolicyCertificateFromFile(policyFile)
	if err != nil {
		return err
	}

	err = updater.UpdateWithKeepExisting(ctx, server.Conn, nil, nil, nil, nil, nil, []common.PolicyDocument{pc})
	if err != nil {
		return err
	}

	if err := server.Updater.CoalescePayloadsForDirtyDomains(ctx); err != nil {
		return fmt.Errorf("coalescing payloads: %w", err)
	}

	// Update SMT.
	if err := server.Updater.UpdateSMT(ctx); err != nil {
		return fmt.Errorf("updating SMT: %w", err)
	}

	// Cleanup.
	if err := server.Updater.Conn.CleanupDirty(ctx); err != nil {
		return fmt.Errorf("cleaning up DB: %w", err)
	}

	newRoot, err := server.Conn.LoadRoot(ctx)
	if err != nil {
		return err
	}
	if root == nil {
		fmt.Printf("MHT root value initially set to %v\n", newRoot)
	} else if bytes.Equal(root[:], newRoot[:]) {
		fmt.Printf("MHT root value was not updated (%v)\n", newRoot)
	} else {
		fmt.Printf("MHT root value updated from %v to %v\n", root, newRoot)
	}

	return nil
}

func writeSampleConfig() error {
	dbConfig := db.NewConfig(
		mysql.WithDefaults(),
		mysql.WithEnvironment(),
		mysql.WithLocalSocket("/var/run/mysqld/mysqld.sock"),
	)
	conf := &config.Config{
		DBConfig:            dbConfig,
		CTLogServerURLs:     []string{"https://ct.googleapis.com/logs/xenon2023/"},
		CertificatePemFile:  "tests/testdata/servercert.pem",
		PrivateKeyPemFile:   "tests/testdata/serverkey.pem",
		HttpAPIPort:         8443,
		CsvIngestionMaxRows: 1000 * 1000,

		UpdateAt: util.NewTimeOfDay(3, 00, 00, 00),
		UpdateTimer: util.DurationWrap{
			Duration: 24 * time.Hour,
		},
	}

	return config.WriteConfigurationToFile(flag.Arg(0), conf)
}

func run(updateNow bool) error {
	ctx := context.Background()

	// Set SIGTERM handler. The context we get is cancelled if one of those signals is caught.
	ctx = util.ContextWithCancelOnSignal(ctx, waitForExitBeforePanicTime, syscall.SIGTERM, syscall.SIGINT)

	// Load configuration and run with it.
	config, err := config.ReadConfigFromFile(flag.Arg(0))
	if err != nil {
		return err
	}

	return runWithConfig(ctx, config, updateNow)
}

// runWithConfig examines the configuration, and according to its values, starts a timer to
// run the update cycle at the corresponding time.
func runWithConfig(
	ctx context.Context,
	conf *config.Config,
	updateNow bool,
) error {

	server, err := mapserver.NewMapServer(ctx, conf)
	if err != nil {
		return err
	}
	root, err := server.Conn.LoadRoot(ctx)
	if err != nil {
		return err
	}
	base64PublicKey, err := util.RSAPublicToDERBase64(server.Cert.PublicKey.(*rsa.PublicKey))
	if err != nil {
		return fmt.Errorf("error converting public key to DER base64: %w", err)
	}
	if root == nil {
		fmt.Printf("Running empty map server (%s) with public key: %s\n", VERSION, base64PublicKey)
	} else {
		fmt.Printf("Running map server (%s) with root: %x and public key: %s\n", VERSION, *root, base64PublicKey)
	}

	// Should update now?
	if updateNow {
		err := server.PruneAndUpdate(ctx)
		if err != nil {
			return fmt.Errorf("performing initial update: %w", err)
		}
	}

	// Set update cycle timer.
	util.RunWhen(ctx, conf.UpdateAt.NextTimeOfDay(), conf.UpdateTimer.Duration,
		func(ctx context.Context) {
			updatePossible, err := server.PruneAndUpdateIfPossible(ctx)
			if err != nil {
				fmt.Printf("ERROR: update returned %s\n", err)
			}
			if !updatePossible {
				fmt.Printf("WARNING: Unable to schedule update due to currently running update (CT log fetching and map server ingestion speed may be too low) at %s\n", time.Now().UTC().Format(time.RFC3339))
			}
		})

	// Listen in responder.
	err = server.ListenWithoutTLS(ctx)

	// Regardless of the error, clean everything up.
	cleanUp()

	// Return the error from the responder.
	return err
}

func cleanUp() {
	fmt.Println("cleaning up")
}

func manageError(err error) int {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	fmt.Println("exiting")
	return 0
}
