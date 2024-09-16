//go:build debug

package pipeline

const DebugEnabledType string = "debug"
const DebugEnabled bool = true

func DebugPrintf(format string, args ...any) {
	_debugPrintFunc(format, args...)
}
