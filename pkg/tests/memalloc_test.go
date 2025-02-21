package tests_test

import (
	"testing"

	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/stretchr/testify/require"
)

func TestAllocsPerRunGlobal(t *testing.T) {
	var a []int
	// Test noop.
	allocs := tests.AllocsPerRun(func() {})
	require.Equal(t, 0, allocs)
	// Test simple function.
	allocs = tests.AllocsPerRun(func() {
		a = make([]int, 1)
	})
	require.Equal(t, 1, allocs)
	// To use the slice.
	require.NotEmpty(t, a)

	// Test embedded calls.
	fcn := func() {
		a = make([]int, 3)
	}
	allocs = tests.AllocsPerRun(func() {
		fcn()
	})
	require.Equal(t, 1, allocs)

	// Test noop goroutine.
	done := make(chan struct{})
	allocs = tests.AllocsPerRun(func() {
		go func() {
			done <- struct{}{}
		}()
		// Wait until done.
		<-done
	})
	// There seems to be a slight overhead when running/syncing with a goroutine.
	require.Equal(t, 4, allocs)

	// Test noop goroutine again.
	done = make(chan struct{})
	allocs = tests.AllocsPerRun(func() {
		go func() {
			done <- struct{}{}
		}()
		// Wait until done.
		<-done
	})
	// The overhead changes when goroutines/channels have been used already.
	require.Equal(t, 1, allocs)

	// Test goroutine.
	done = make(chan struct{})
	allocs = tests.AllocsPerRun(func() {
		go func() {
			fcn()
			done <- struct{}{}
		}()
		// Wait until done.
		<-done
	})
	t.Logf("goroutine # allocs: %d", allocs)
	// Subtract the overhead to the end result.
	require.Equal(t, 1, allocs-1)
}
