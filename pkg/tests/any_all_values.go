package tests

import "github.com/stretchr/testify/require"

func CheckAnyIsTrue[P any](t T, s []P, checkFunc func(T, P) bool) {
	for i, v := range s {
		if checkFunc(t, v) {
			t.Logf("value %v at index %d is true", v, i)
			return
		}
	}
	require.FailNow(t, "no value returned true", "slice: %v", s)
}

func CheckAllAreTrue[P any](t T, s []P, checkFunc func(T, P) bool) {
	for i, v := range s {
		if !checkFunc(t, v) {
			require.FailNow(t, "value returned false", "at index %d value: %v", i, v)
			return
		}
	}
	t.Logf("all values returned true in slice %s", s)
}
