package debug

import (
	"fmt"
	"unsafe"
)

func Chan2UintPtr[T any](c chan T) uintptr {
	return *(*uintptr)(unsafe.Pointer(&c))
}

func Chan2str[T any](c chan T) string {
	return fmt.Sprintf("0x%x", Chan2UintPtr(c))
}
