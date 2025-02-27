package tests

import (
	"os"
	"runtime"
	"runtime/pprof"

	"github.com/stretchr/testify/require"
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

// AllocsPerRunPreciseWithProfile is similar to AllocsPerRun, but it writes a memory profile
// with the provided name if the allocation count is bigger than expected.
// Start the test process by first calling StopMemoryProfile() as the first thing the test does.
func AllocsPerRunPreciseWithProfile(t T, testFunc func(), maxAllocs int, profileFilename string) {
	runtime.GC()
	runtime.Gosched()

	var statsBefore, statsAfter runtime.MemStats

	runtime.ReadMemStats(&statsBefore)

	StartMemoryProfile()
	testFunc()
	StopMemoryProfile()

	runtime.ReadMemStats(&statsAfter)
	allocs := int(statsAfter.Mallocs) - int(statsBefore.Mallocs)

	if allocs > maxAllocs {
		DumpMemoryProfile(t, profileFilename)
	}
	require.LessOrEqual(t, allocs, maxAllocs)
}

func StopMemoryProfile() {
	runtime.MemProfileRate = 0
}

func StartMemoryProfile() {
	runtime.MemProfileRate = 1
}

// DumpMemoryProfile dumps a memory profile.
// For best results, isolate the region to measure by stopping memory profiling right at the
// beginning of the application, and then start memory profiling only right before the region of
// interest.
// A good visualization for small uncounted allocations is to run:
// go tool pprof -alloc_objects -web filename
func DumpMemoryProfile(t T, fileName string) {
	StopMemoryProfile()
	f, err := os.Create(fileName)
	require.NoError(t, err)

	err = pprof.Lookup("heap").WriteTo(f, 0) // use "heap" or "allocs"
	require.NoError(t, err)

	err = f.Close()
	require.NoError(t, err)
}
