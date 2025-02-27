package tests

import (
	"testing"
	"time"
)

// ExtendTimeForBenchmark mimics the behavior of calling b.N times the benchmark function, by
// sleeping the appropriate amount of time.
// Use:
//
//	func BenchmarkMyFunc(b *testing.B) {
//		defer tests.ExtendTimeForBenchmark(b)()
//		benchmarkMyFuncOnce()
//	}
//
// The benchmark will correctly measure the time/op now.
func ExtendTimeForBenchmark(b *testing.B) func() {
	fcn := func() {
		// Time needed for one run.
		// oneRun := time.Since(t0)
		oneRun := b.Elapsed()

		// Do the N-1 pending iterations by sleeping.
		for i := 0; i < b.N-1; i++ {
			time.Sleep(oneRun)
		}
	}
	return fcn
}
