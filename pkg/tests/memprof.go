package tests

import (
	"runtime"
)

func AllocsPerRunGlobal(testFunc func()) int {
	var statsBefore, statsAfter runtime.MemStats

	runtime.ReadMemStats(&statsBefore)

	testFunc()

	runtime.ReadMemStats(&statsAfter)

	return int(statsAfter.Mallocs) - int(statsBefore.Mallocs)
}
