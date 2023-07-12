package util_test

import (
	"context"
	"testing"
	"time"

	"github.com/netsec-ethz/fpki/pkg/util"
	"github.com/stretchr/testify/require"
)

func TestNewTickingFunction(t *testing.T) {
	// Context that we control.
	ctx, cancelF := context.WithCancel(context.Background())

	// Variable that keeps track of how many times the function is called.
	callAmount := 0

	// Create the ticker.
	interval := 10 * time.Millisecond
	util.NewTickingFunction(ctx, interval, func() {
		callAmount++
	})

	// Wait just short of ten times the interval.
	time.Sleep(10*interval - time.Millisecond)
	require.Equal(t, 10, callAmount)

	// Stop the ticking function.
	cancelF()

	// Wait another interval.
	time.Sleep(interval)

	// Check number of times called.
	require.Equal(t, 10, callAmount)
}
