package util_test

import (
	"context"
	"testing"
	"time"

	"github.com/netsec-ethz/fpki/pkg/util"
	"github.com/stretchr/testify/require"
)

func TestRunWhen(t *testing.T) {
	cases := map[string]struct {
		when          time.Time
		interval      time.Duration
		expectedCalls int

		sleepInTestOverride time.Duration // if set, this will be the sleep time
	}{
		"nowait": {
			when:          time.Now().Add(-time.Hour), // no wait
			interval:      10 * time.Millisecond,
			expectedCalls: 10,
		},
		"after500ms": {
			when:          time.Now().Add(500 * time.Millisecond),
			interval:      10 * time.Millisecond,
			expectedCalls: 3,
		},
		"calledOnce": {
			when:                time.Now().Add(time.Millisecond),
			interval:            10 * time.Second,
			expectedCalls:       1,
			sleepInTestOverride: 2 * time.Millisecond, // override the sleepWait in the test
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			now := time.Now()

			// New context that we can manually cancel.
			ctx, cancelF := context.WithCancel(context.Background())

			// Variable that keeps track of how many times the function is called.
			callAmount := 0

			// Run the function when specified.
			util.RunWhen(ctx, tc.when, tc.interval, func(c context.Context) {
				callAmount++
				t.Logf("called %d times", callAmount)
			})

			// Wait just one millisecond short of max(when, now) + expectedCalls *interval
			sleepTime := time.Duration(tc.expectedCalls) * tc.interval
			if tc.when.After(now) {
				sleepTime += tc.when.Sub(now)
			}
			sleepTime -= time.Millisecond
			// Unless sleepInTestOverride was specified.
			if tc.sleepInTestOverride != 0 {
				sleepTime = tc.sleepInTestOverride
			}

			// Sleep that amount of time.
			t.Logf("about to sleep for %s", sleepTime)
			time.Sleep(sleepTime)

			// Stop the ticking function.
			cancelF()

			// Check.
			require.Equal(t, tc.expectedCalls, callAmount)

			// Wait another interval just for good measure.
			time.Sleep(sleepTime)

			// Check number of times called didn't increment (cancelling the context stopped it).
			require.Equal(t, tc.expectedCalls, callAmount)
		})
	}
}
