package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/netsec-ethz/fpki/pkg/util"
)

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
	createConfig := flag.Bool("createConfig", false,
		"Create configuration file specified by positional argument")
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		return 1
	}

	if *createConfig {
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

	// Load configuration.
	config, err := ReadConfigFromFile(flag.Arg(0))
	if err == nil {
		err = runWithConfig(config,
			*updateVar)
	}

	// Print message in case of error.
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	return 0
}

func runWithConfig(c *Config, updateNow bool) error {
	return nil
}
