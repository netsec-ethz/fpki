package pipeline

import (
	"context"
)

type SourceLike interface {
	StageLike
	Wait(context.Context) error
	GetSourceBase() *SourceBase
}

func IsSource(s StageLike) bool {
	_, ok := s.(SourceLike)
	return ok
}

type Source[OUT any] struct {
	*Stage[None, OUT]
	SourceBase
	// Channel used for the source, if configured with one.
	sourceIncomingCh  chan OUT
	sourceProcessFunc func(OUT) ([]int, error)
}

var _ SourceLike = (*Source[int])(nil)

func NewSource[OUT any](
	name string,
	options ...option[None, OUT],
) *Source[OUT] {
	s := &Source[OUT]{
		Stage: NewStage[None, OUT](name, options...),
	}

	for _, opt := range options {
		opt.ApplyToSource(s)
	}

	return s
}

func WithSourceFunction[OUT any]( // deleteme
	generator func() ([]OUT, []int, error),
) option[None, OUT] {
	return newSourceOption(func(s *Source[OUT]) {
		s.ProcessFunc = func(in None) ([]OUT, []int, error) {
			s.sourceIncomingCh = nil
			return generator()
		}
	})
}

// WithSourceChannel sets this source to produce as much output as the incoming channel provides.
// The processing function is called for each value to determine the output channel and error.
func WithSourceChannel[OUT any]( // deleteme?
	incomingCh *chan OUT,
	processFunction func(in OUT) ([]int, error),
) option[None, OUT] {
	return newSourceOption(
		func(s *Source[OUT]) {
			// Set the source incoming channel initially to the value of the pointer.
			s.sourceIncomingCh = *incomingCh
			s.sourceProcessFunc = processFunction // Local copy of the processing function.

			// Every time the stage resumes, set the source incoming channel.
			// Since the pointed value might have changed, this is necessary between each resume
			// calls.
			// Additionally we resize the outs slice to the amount of out channels we have.
			outs := make([]OUT, 0)
			s.onResume = func() {
				DebugPrintf("[%s] WithSourceChannel restoring source channel to %s\n",
					s.Name, chanPtr(*incomingCh))
				s.sourceIncomingCh = *incomingCh
				DebugPrintf("[%s] WithSourceChannel resizing internal out slice to size %d\n",
					s.Name, len(s.OutgoingChs))
				outs = make([]OUT, len(s.OutgoingChs))
			}

			s.ProcessFunc = func(in None) ([]OUT, []int, error) {
				DebugPrintf("[%s] source.ProcessFunc: channel is: %s\n",
					s.Name, chanPtr(s.sourceIncomingCh))

				if in, ok := <-s.sourceIncomingCh; ok {
					DebugPrintf("[%s] source channel %s got value: %v\n",
						s.Name, chanPtr(s.sourceIncomingCh), in)
					outChs, err := s.sourceProcessFunc(in)
					outs = outs[:0] // reuse storage
					// Copy the same value for all the out channels.
					for i := 0; i < len(outChs); i++ {
						outs = append(outs, in)
					}
					DebugPrintf("[%s] source channel outs: %v, chs: %v, err: %v\n",
						s.Name, outs, outChs, err)
					return outs, outChs, err
				}

				DebugPrintf("[%s] source channel %s is closed, no more data\n",
					s.Name, chanPtr(s.sourceIncomingCh))
				// When the incoming channel is closed, return no more data.
				return nil, nil, NoMoreData
			}
		},
	)
}

// WithSourceSlice uses the slice as the input sequence for the source.
func WithSourceSlice[OUT any](
	incomingValues *[]OUT,
	processFunction func(in OUT) (int, error),
) option[None, OUT] {
	return newSourceOption(
		func(s *Source[OUT]) {
			s.onResume = func() {
				s.sourceIncomingCh = make(chan OUT)
				DebugPrintf("[%s] WithSourceSlice restoring source channel to %s\n",
					s.Name, chanPtr(s.sourceIncomingCh))
				go func() {
					for _, in := range *incomingValues {
						s.sourceIncomingCh <- in
					}
					close(s.sourceIncomingCh)
				}()
			}

			processFunction := processFunction // Local copy of the processing function.
			outs := make([]OUT, 1)
			outChs := make([]int, 1)
			s.ProcessFunc = func(in None) ([]OUT, []int, error) {
				DebugPrintf("[%s] source.ProcessFunc: channel is: %s\n",
					s.Name, chanPtr(s.sourceIncomingCh))
				for in := range s.sourceIncomingCh {
					DebugPrintf("[%s] source channel %s got value: %v\n",
						s.Name, chanPtr(s.sourceIncomingCh), in)
					outCh, err := processFunction(in)
					DebugPrintf("[%s] source channel processed value: %v, out ch: %d, err: %v\n",
						s.Name, in, outCh, err)
					outs[0] = in
					outChs[0] = outCh
					return outs, outChs, err
				}
				DebugPrintf("[%s] source channel %s is closed, no more data\n",
					s.Name, chanPtr(s.sourceIncomingCh))
				// When the incoming channel is closed, return no more data.
				return nil, nil, NoMoreData
			}
		},
	)
}

func (s *Source[OUT]) Wait(ctx context.Context) error {
	return <-s.TopErrCh
}

func (s *Source[OUT]) Prepare(ctx context.Context) {
	// Regular stage preparation:
	SourceAsStage(s).Prepare(ctx)

	s.TopErrCh = make(chan error)
	DebugPrintf("[%s] TopErr is %s, incoming[0] is %s\n",
		s.Name, chanPtr(s.TopErrCh), chanPtr(s.IncomingChs[0]))

	// As a source, we generate data by sending none to our incoming channel,
	// until our errCh is closed.
	// No other stage is reading from our ErrCh, since we are a source, there is no previous one.
	go func(errCh chan error) {
		DebugPrintf("[%s] source.Prepare spawning continuous send, err chan: %s\n",
			s.Name, chanPtr(errCh))
		for {
			select {
			case s.IncomingChs[0] <- None{}:
				DebugPrintf("[%s] source to itself None\n", s.Name)
			case err := <-errCh:
				DebugPrintf("[%s] source's orig. errCh (%s): %v. Sending to TopChan %s\n",
					s.Name, chanPtr(errCh), err, chanPtr(s.TopErrCh))
				// Close incoming.
				DebugPrintf("[%s] source closing incoming %s\n", s.Name, chanPtr(s.IncomingChs[0]))
				close(s.IncomingChs[0])
				if err != nil {
					s.TopErrCh <- err // might block, but this goroutine is done anyways.
				}
				DebugPrintf("[%s] source closing TopErr %s\n", s.Name, chanPtr(s.TopErrCh))
				close(s.TopErrCh)
				return
			}
		}
	}(s.ErrCh)
}

func (s *Source[OUT]) SourceProcessFunc() func(OUT) ([]int, error) {
	return s.sourceProcessFunc
}

type SourceBase struct {
	TopErrCh chan error // This error is not propagated to other stages.
}

func (s *SourceBase) GetSourceBase() *SourceBase {
	return s
}

func SourceAsStage[OUT any](s *Source[OUT]) *Stage[None, OUT] {
	return s.Stage
}
