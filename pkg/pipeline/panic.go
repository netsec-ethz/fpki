//go:build panic

package pipeline

import "fmt"

func debugPrintf(format string, args ...any) {
	fmt.Printf(format, args...)
}
