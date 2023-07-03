package util

import (
	"fmt"
	"strconv"
	"time"

	"golang.org/x/exp/constraints"
)

func TimeFromSecs(secs int) time.Time {
	return time.Unix(int64(secs), 0)
}

func SecsFromTime(t time.Time) int {
	return int(t.Unix())
}

// ParseTimeOfDay returns a time.Time constructed from strings such as 15:35:55 or 15:55:55.123456.
// The returned Time will have the rest of the fields to zero, and it's constructed using the
// library function time.TimeOnly. This function is here only for reference and tests.
func ParseTimeOfDay(s string) (time.Time, error) {
	// Using `TimeOnly` the library checks if there are milliseconds, etc after a dot, optionally,
	// so this layout also accepts strings such as 13:35:55.123 or 13:35:55.123456789 .
	// Because the documentation doesn't specify this as the behavior, there is a test that checks
	// that this function behaves as expected.
	return time.Parse(time.TimeOnly, s)
}

// parseInteger parses a string into a integer. The type can be explicitly indicated or inferred
// from min and max.
// Note that with Go 1.20
func parseInteger[T constraints.Integer](s string, min, max T, name string) (T, error) {
	var z T // time zero, to be able to return a T value.

	i, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return z, fmt.Errorf("%s is not a %s", s, name)
	}
	if i < int64(min) || i > int64(max) {
		return z, fmt.Errorf("%v is not between %v and %v", i, min, max)
	}
	return T(i), nil
}
