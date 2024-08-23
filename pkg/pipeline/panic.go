//go:build panic

package pipeline

import "fmt"

const DebugEnabled string = "panic"

func debugPrintf(format string, args ...any) {
	fmt.Printf(format, args...)
}
