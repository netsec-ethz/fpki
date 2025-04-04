package tests

import (
	"flag"
	"os"
	"runtime"
	"runtime/pprof"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func AllocsPerRun(f func(b B)) int {
	// Disallow running this function concurrently.
	modifyOsArgsMu.Lock()
	defer func() {
		modifyOsArgsMu.Unlock()
	}()

	testing.Init()

	prevOsArgs := os.Args
	os.Args = append(os.Args, "-test.benchtime=1x")
	flag.Parse()

	res := testing.Benchmark(func(b *testing.B) {
		f(b)
	})
	os.Args = prevOsArgs
	return int(res.MemAllocs)
}

// AllocsPerRunPreciseWithProfile is similar to AllocsPerRun, but it writes a memory profile
// with the provided name if the allocation count is bigger than expected.
// Start the test process by first calling StopMemoryProfile() as the first thing the test does.
func AllocsPerRunPreciseWithProfile(t T, testFunc func(B), maxAllocs int, profileFilename string) {
	allocs := AllocsPerRun(func(b B) {
		StartMemoryProfile()
		testFunc(b)
	})

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

	// err = pprof.Lookup("heap").WriteTo(f, 0) // use "heap" or "allocs"
	err = pprof.Lookup("allocs").WriteTo(f, 0) // use "heap" or "allocs"
	require.NoError(t, err)

	err = f.Close()
	require.NoError(t, err)
}

// modifyOsArgsMu is a private mutex necessary to lock/unlock when running the AllocsPerRun
// function, as the function modifies os.Args to run the function exactly once.
var modifyOsArgsMu = sync.Mutex{}
