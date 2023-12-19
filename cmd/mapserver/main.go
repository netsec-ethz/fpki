package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/db/mysql"
	"github.com/netsec-ethz/fpki/pkg/mapserver"
	"github.com/netsec-ethz/fpki/pkg/mapserver/config"
	"github.com/netsec-ethz/fpki/pkg/util"
)

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
	updateVar := flag.Bool("updateNow", true, "Immediately trigger an update cycle")
	createSampleConfig := flag.Bool("createSampleConfig", false,
		"Create configuration file specified by positional argument")
	flag.Parse()

	// We need the configuration file as the first positional argument.
	if flag.NArg() != 1 {
		flag.Usage()
		return 1
	}

	var err error
	if *createSampleConfig {
		err = writeSampleConfig()
	} else {
		err = run(*updateVar)
	}

	// We have finished. Probably the context created in run was been cancelled (exit request).
	// Print message in case of error.
	return manageError(err)
}

func writeSampleConfig() error {
	dbConfig := db.NewConfig(
		mysql.WithDefaults(),
		mysql.WithEnvironment(),
		mysql.WithLocalSocket("/var/run/mysqld/mysqld.sock"),
	)
	conf := &config.Config{
		DBConfig:           dbConfig,
		CTLogServerURLs:    []string{"https://ct.googleapis.com/logs/xenon2023/"},
		CertificatePemFile: "tests/testdata/servercert.pem",
		PrivateKeyPemFile:  "tests/testdata/serverkey.pem",

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
	ctx = util.SetSignalHandler(ctx, waitForExitBeforePanicTime, syscall.SIGTERM, syscall.SIGINT)

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
			err := server.PruneAndUpdate(ctx)
			if err != nil {
				fmt.Printf("ERROR: update returned %s\n", err)
			}
		})

	// Listen in responder.
	err = server.Listen(ctx)

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
