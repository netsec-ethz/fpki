//go:build panic

package pipeline

import "fmt"

const DebugEnabledType string = "panic"
const DebugEnabled bool = true

func DebugPrintf(format string, args ...any) {
	fmt.Printf(format, args...)
}
