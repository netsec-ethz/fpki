package tests_test

import (
	"testing"

	"github.com/netsec-ethz/fpki/pkg/sync"
	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/stretchr/testify/require"
)

func TestAllocsPerRun(t *testing.T) {
	invokeCount := 0
	allocs := tests.AllocsPerRun(func(tests.B) {
		invokeCount = invokeCount + 1
		dummyLoadFunction(1024)
	})
	require.Equal(t, 1, invokeCount)
	require.Equal(t, 1024, allocs)
}

func TestAllocsPerRunGlobal(t *testing.T) {
	var a []int

	// Test noop.
	allocs := tests.AllocsPerRun(func(tests.B) {})
	require.Equal(t, 0, allocs)
	// Test simple function.
	allocs = tests.AllocsPerRun(func(tests.B) {
		a = make([]int, 1)
	})
	require.Equal(t, 1, allocs)
	// To use the slice.
	require.NotEmpty(t, a)

	// Test embedded calls.
	fcn := func() {
		a = make([]int, 3)
	}
	allocs = tests.AllocsPerRun(func(tests.B) {
		fcn()
	})
	require.Equal(t, 1, allocs)

	// Test several goroutines at once.
	const N = 10
	const Load = 1024
	l := sync.NewSpinLock(N)

	// Create routines already.
	for w := range N {
		go func(id int) {
			l.Lock(id)
			defer l.UnLock(id)

			// Work here.
			dummyLoadFunction(Load)
		}(w)
	}

	l.Start() // Some routines may allocate memory before we measure, we'll take it into account.
	allocs = tests.AllocsPerRun(func(b tests.B) {
		l.Wait()
	})
	// Check that the measuread allocated mem. is 0<= x <= N*Load
	require.GreaterOrEqual(t, allocs, 0)
	require.LessOrEqual(t, allocs, N*Load)
}

func dummyLoadFunction(n int) {
	n = n - 1
	useless := make([][]byte, n)
	for i := range len(useless) {
		useless[i] = make([]byte, 1)
	}
}
