package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"syscall"
	"time"

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

	if *createSampleConfig {
		config := &Config{
			UpdateAt: util.NewTimeOfDay(3, 00, 00, 00),
			UpdateTimer: util.DurationWrap{
				Duration: 24 * time.Hour,
			},
		}
		err := WriteConfigurationToFile(flag.Arg(0), config)
		if err != nil {
			panic(err)
		}
	}

	ctx := context.Background()

	// Set SIGTERM handler. The context we get is cancelled if one of those signals is caught.
	ctx = util.SetSignalHandler(ctx, waitForExitBeforePanicTime, syscall.SIGTERM, syscall.SIGINT)

	// Load configuration and run with it.
	config, err := ReadConfigFromFile(flag.Arg(0))
	if err == nil {
		err = runWithConfig(
			ctx,
			config,
			*updateVar,
		)
	}

	// We have finished. Print message in case of error.
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	return 0
}

// runWithConfig examines the configuration, and according to its values, starts a timer to
// run the update cycle at the corresponding time.
func runWithConfig(
	ctx context.Context,
	c *Config,
	updateNow bool,
) error {

	server, err := NewMapserver()
	if err != nil {
		return err
	}

	// Should update now?
	if updateNow {
		err := server.Update()
		if err != nil {
			return fmt.Errorf("performing initial update: %w", err)
		}
	}
	// Set update cycle timer.

	// Listen in responder.

	// Wait forever until cancellation.
	<-ctx.Done()

	return nil
}