package tests

import (
	"flag"
	"os"
	"strings"
)

// InsideTest returns true if the process is running inside a test.
func InsideTest() bool {
	return strings.HasSuffix(os.Args[0], ".test") ||
		flag.Lookup("test.v") != nil
}
