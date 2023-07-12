package util

import (
	"context"
	"time"
)

// NewTickingFunction creates a new ticker that runs the function inmediately and every `dur` interval.
// It relies on `time.Ticker`, so this function will adjust the interval depending on the duration
// of the execution of the function. It can also drop ticks.
// The function stops running the function if the context is cancelled.
func NewTickingFunction(
	ctx context.Context,
	dur time.Duration,
	runWhenTick func(),
) {

	ticker := time.NewTicker(dur)
	go func(ticker *time.Ticker) {
		for {
			runWhenTick()
			select {
			case <-ticker.C:
				continue
			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}(ticker)
}
