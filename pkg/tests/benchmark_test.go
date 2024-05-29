package tests_test

import (
	"testing"
	"time"

	"github.com/netsec-ethz/fpki/pkg/tests"
)

// Both benchmarks should give around the same answer for ns/op.

func BenchmarkSleepWithLoop(b *testing.B) {
	for i := 0; i < b.N; i++ {
		time.Sleep(50 * time.Millisecond)
	}
}

func BenchmarkSleepWithExtender(b *testing.B) {
	defer tests.ExtendTimeForBenchmark(b)()
	time.Sleep(50 * time.Millisecond)
}
