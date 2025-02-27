package util

import (
	"errors"
	"os"
)

// ShutdownFunction is a function that runs all registered shutdown functions.
// It only works if the main function exits with a return, and not on os.Exit functions.
// Replace os.Exit calls with Exit(int) here to allow the shutdown function to work.
var ShutdownFunction = func() error {
	var errs []error
	for _, fcn := range shutdownFuncs {
		errs = append(errs, fcn())
	}
	return errors.Join(errs...)
}

// Exit acts as a wrapper around os.Exit, but calling the shutdown functions before exiting.
func Exit(code int) {
	ShutdownFunction()
	os.Exit(code)
}

func RegisterShutdownFunc(fcn func() error) {
	shutdownFuncs = append(shutdownFuncs, fcn)
}

// shutdownFuncs collects all the functions to run at shutdown time.
var shutdownFuncs []func() error
