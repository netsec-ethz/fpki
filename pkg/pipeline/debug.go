//go:build debug

package pipeline

const DebugEnabled string = "debug"

func debugPrintf(format string, args ...any) {
	_debugPrintFunc(format, args...)
}
