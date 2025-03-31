package util

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"time"
)

// ContextWithCancelOnSignal builds a context that gets cancelled in case of receiving one of the
// signals passed as arguments.
// Additionally there is a panic after `waitTime` unless we cleanly exit the process, to avoid
// leaving the process dangling forever.
func ContextWithCancelOnSignal(
	ctx context.Context,
	waitTime time.Duration,
	signals ...os.Signal,
) context.Context {

	ctx, cancel := context.WithCancel(ctx)
	stop := make(chan os.Signal, len(signals))
	signal.Notify(stop, signals...)

	// Forever listen to the signals, and if received, cancel the context.
	go func() {
		defer signal.Stop(stop)
		select {
		case <-stop:
			// We have received one of those signals: cancel the context we returned.
			cancel()
		case <-ctx.Done():
			// Cleanly exit if somebody else cancelled the context we returned.
		}
	}()

	// Forever wait until the context is cancelled, and then wait for 10 more seconds.
	// If the main go routine finishes before that, the panic will not execute.
	go func() {
		<-ctx.Done()

		fmt.Fprintf(os.Stderr, "\nReceived signal, will exit in %s\n",
			waitTime)
		// Wait.
		time.Sleep(waitTime)

		// And panic to notify that the main go routine still didn't finish.
		panic(fmt.Errorf("main routine still running after %s, shutting down via panic",
			waitTime))
	}()

	// This context will be cancelled if the signal is trapped.
	return ctx
}
