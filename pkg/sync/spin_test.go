package sync

import (
	"testing"

	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/stretchr/testify/require"
)

func TestSpinLock(t *testing.T) {
	N := 100
	l := NewSpinLock(N)

	result := 0
	workerFcn := func(id int) {
		l.Lock(id)
		defer l.UnLock(id)

		// Work.
		result += id
	}

	for w := range N {
		go workerFcn(w)
	}

	l.Start()
	t.Log("waiting")
	l.Wait()
	t.Log("done")

	// Check value.
	expected := N * (N - 1) / 2
	require.Equal(t, expected, result)
}

func TestSpinLockNoMemAllocation(t *testing.T) {
	N := 100
	l := NewSpinLock(N)

	// Spin the workers.
	workerFcn := func(id int) {
		l.Lock(id)
		defer l.UnLock(id)
	}
	for w := range N {
		go workerFcn(w)
	}

	// Measure mem allocations of the lock.
	l.Start()
	allocs := tests.AllocsPerRun(t, func(b tests.B) {
		l.Wait()
	})
	t.Logf("allocations = %d", allocs)
	require.Equal(t, 0, allocs)
}
