//go:build debug

package pipeline

import (
	"fmt"
	"sort"
	"sync"
	"time"
	"unsafe"
)

func debugPrintf(format string, args ...any) {
	// fmt.Printf(format, args...)
	_debugPrintFunc(format, args...)
}

type debugLine struct {
	Time time.Time
	Line string
}

var debugLines []debugLine
var debugLinesMu sync.Mutex

func _debugPrintFunc(format string, args ...any) {
	t := time.Now()
	line := fmt.Sprintf(format, args...)
	debugLinesMu.Lock()
	defer debugLinesMu.Unlock()
	debugLines = append(debugLines, debugLine{
		Time: t,
		Line: line,
	})
}

func PrintAllDebugLines() {
	sort.Slice(debugLines, func(i, j int) bool {
		return debugLines[i].Time.Before(debugLines[j].Time)
	})
	for i, d := range debugLines {
		if i > 999 {
			// Max of 1000 lines of output.
			fmt.Printf("... more output (%d lines omitted) ...\n", len(debugLines)-1000)
			break
		}
		fmt.Printf("[%3d] [%30s] %s",
			i,
			d.Time.Format(time.StampNano),
			d.Line,
		)
	}
}

func chanUintPtr[T any](c chan T) uintptr {
	return *(*uintptr)(unsafe.Pointer(&c))
}

func chanPtr[T any](c chan T) string {
	return fmt.Sprintf("0x%x", chanUintPtr(c))
}
