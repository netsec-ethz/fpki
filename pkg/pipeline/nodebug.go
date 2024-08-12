//go:build !debug

package pipeline

import (
	"unsafe"
)

func debugPrintf(format string, args ...any) {}

func PrintAllDebugLines() {}

func chanUintPtr[T any](c chan T) uintptr {
	return *(*uintptr)(unsafe.Pointer(&c))
}

func chanPtr[T any](c chan T) string {
	return ""
}
