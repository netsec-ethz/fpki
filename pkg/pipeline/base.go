package pipeline

import (
	"fmt"
)

type Base struct {
	Name   string
	ErrCh  chan error // To be read by the previous stage (or trigger, if this is Source).
	StopCh chan none
}

type none struct{}

func NewBase(name string) *Base {
	return &Base{
		Name: name,
	}
}

func (b *Base) Prepare() {
	b.ErrCh = make(chan error)
	b.StopCh = make(chan none)
}

func (b *Base) breakPipeline(err error) error {
	debugPrintf("[%s] Base: breaking pipeline\n", b.Name)
	if err != nil {
		// Propagate error backwards.
		b.ErrCh <- err
	}
	// Close our own error channel.
	close(b.ErrCh)
	// Close the stop channel indicator.
	close(b.StopCh)
	debugPrintf("[%s] Base: all done\n", b.Name)
	return err
}

func debugPrintf(format string, args ...any) {
	// fmt.Fprintf(os.Stdout, format, args...)
	// if err := os.Stdout.Sync(); err != nil {
	// 	panic(err)
	// }
	fmt.Printf(format, args...)
}
