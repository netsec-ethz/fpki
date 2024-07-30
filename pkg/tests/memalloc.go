package tests

import (
	"runtime"
)

// AllocsPerRun measures all the calls to malloc that happen in the process during the
// call to the testFunc. It includes goroutines allocations and no warm up calls.
func AllocsPerRun(testFunc func()) int {
	var statsBefore, statsAfter runtime.MemStats

	runtime.ReadMemStats(&statsBefore)

	testFunc()

	runtime.ReadMemStats(&statsAfter)

	return int(statsAfter.Mallocs) - int(statsBefore.Mallocs)
}
