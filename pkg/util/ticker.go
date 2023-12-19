package util

import (
	"context"
	"time"
)

// RunWhen executes the function at the specified time.Time. If said time is in the
// past, it will execute it immediately. It then executes the function repeatedly every interval.
// It will adapt the internal ticker and even skip some ticks, so that the execution times of
// the fuction are independent from the duration of the execution itself.
// The function stops being executed when the context is cancelled.
func RunWhen(
	ctx context.Context,
	when time.Time,
	repeat time.Duration,
	whenTick func(ctx context.Context),
) {

	go func() {
		waiting := time.Until(when)
		timer := time.NewTimer(waiting)
		<-timer.C
		ticker := time.NewTicker(repeat)
		for {
			whenTick(ctx)
			select {
			case <-ticker.C:
				continue
			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()
}
