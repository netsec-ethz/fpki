//go:build !(debug || panic)

package pipeline

import (
	"unsafe"
)

const DebugEnabledType string = "nodebug"
const DebugEnabled bool = false

func DebugPrintf(format string, args ...any) {}

func PrintAllDebugLines() {}

func chanUintPtr[T any](c chan T) uintptr {
	return *(*uintptr)(unsafe.Pointer(&c))
}

func chanPtr[T any](chan T) string {
	return ""
}
