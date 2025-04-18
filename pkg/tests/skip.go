package tests

import (
	"os"
	"testing"
)

// SkipUnless skips a test if the environment variable envVar not is defined
func SkipUnless(t T, envVar string) {
	_, ok := os.LookupEnv(envVar)
	if !ok {
		t.Skipf("skipped due to %s not being defined", envVar)
	}
}

func SkipExpensiveTest(t T) {
	if !testing.Short() {
		SkipUnless(t, "EXPENSIVE_TEST")
	}
}
