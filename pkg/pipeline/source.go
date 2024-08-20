package pipeline

type Source[OUT any] struct {
	*Stage[None, OUT]
	SourceBase
	// Channel used for the source, if configured with one.
	sourceIncomingCh chan OUT
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
		opt.source(s)
	}

	return s
}

func WithSourceFunction[OUT any](
	generator func() ([]OUT, []int, error),
) option[None, OUT] {
	return newSourceOption(func(s *Source[OUT]) {
		s.ProcessFunc = func(in None) ([]OUT, []int, error) {
			s.sourceIncomingCh = nil
			return generator()
		}
	})
}

// Sets this source to produce as much output as the incoming channel provides.
// The processing function is called for each value to determine the output channel and error.
func WithSourceChannel[OUT any](
	incomingCh chan OUT,
	processFunction func(in OUT) (int, error),
) option[None, OUT] {
	return newSourceOption(
		func(s *Source[OUT]) {
			s.sourceIncomingCh = incomingCh

			processFunction := processFunction
			outs := make([]OUT, 1)
			outChs := make([]int, 1)
			s.ProcessFunc = func(in None) ([]OUT, []int, error) {
				debugPrintf("[%s] source.ProcessFunc: channel is: %s\n",
					s.Name, chanPtr(s.sourceIncomingCh))
				for in := range s.sourceIncomingCh {
					debugPrintf("[%s] source channel %s got value: %v\n",
						s.Name, chanPtr(s.sourceIncomingCh), in)
					outCh, err := processFunction(in)
					debugPrintf("[%s] source channel processed value: %v, out ch: %d, err: %v\n",
						s.Name, in, outCh, err)
					outs[0] = in
					outChs[0] = outCh
					return outs, outChs, err
				}
				debugPrintf("[%s] source channel %s is closed, no more data\n",
					s.Name, chanPtr(s.sourceIncomingCh))
				// When the incoming channel is closed, return no more data.
				return nil, nil, NoMoreData
			}
		})
}

func (s *Source[OUT]) Wait() error {
	return <-s.TopErrCh
}

func (s *Source[OUT]) Prepare() {
	// Regular stage preparation:
	SourceAsStage(s).Prepare()

	s.TopErrCh = make(chan error)
	debugPrintf("[%s] TopErr is %s, incoming[0] is %s\n",
		s.Name, chanPtr(s.TopErrCh), chanPtr(s.IncomingChs[0]))

	// As a source, we generate data by sending none to our incoming channel,
	// until our errCh is closed.
	// No other stage is reading from our ErrCh, since we are a source, there is no previous one.
	go func(errCh chan error) {
		debugPrintf("[%s] source.Prepare spawning continuous send, err chan: %s\n",
			s.Name, chanPtr(errCh))
		for {
			select {
			case s.IncomingChs[0] <- None{}:
				debugPrintf("[%s] source to itself None\n", s.Name)
			case err := <-errCh:
				debugPrintf("[%s] source's orig. errCh (%s): %v. Sending to TopChan %s\n",
					s.Name, chanPtr(errCh), err, chanPtr(s.TopErrCh))
				// Close incoming.
				debugPrintf("[%s] source closing incoming %s\n", s.Name, chanPtr(s.IncomingChs[0]))
				close(s.IncomingChs[0])
				if err != nil {
					s.TopErrCh <- err // might block, but this goroutine is done anyways.
				}
				debugPrintf("[%s] source closing TopErr %s\n", s.Name, chanPtr(s.TopErrCh))
				close(s.TopErrCh)
				return
			}
		}
	}(s.ErrCh)
}

type SourceLike interface {
	StageLike
	Wait() error
	GetSourceBase() *SourceBase
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
