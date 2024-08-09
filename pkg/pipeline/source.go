package pipeline

type Source[OUT any] struct {
	*Stage[None, OUT]
	SourceBase
}

var _ SourceLike = (*Source[int])(nil)

func NewSource[OUT any](
	name string,
	options ...stageOption[None, OUT],
) *Source[OUT] {
	return &Source[OUT]{
		Stage: NewStage[None, OUT](name, options...),
	}
}

func WithSourceFunction[OUT any](
	generator func() ([]OUT, []int, error),
) stageOption[None, OUT] {
	return func(s *Stage[None, OUT]) {
		s.ProcessFunc = func(in None) ([]OUT, []int, error) {
			return generator()
		}
	}
}

func (s *Source[OUT]) Wait() error {
	return <-s.TopErrCh
}

func (s *Source[OUT]) Prepare() {
	// Regular stage preparation:
	SourceAsStage(s).Prepare()

	s.TopErrCh = make(chan error)
	debugPrintf("[%s] TopErr is 0x%x\n", s.Name, chanPtr(s.TopErrCh))
	// As a source, we generate data by sending none to our incoming channel,
	// until our errCh is closed.
	// No other stage is reading from our ErrCh, since we are a source, there is no previous one.
	go func(errCh chan error) {
		debugPrintf("[%s] source.Prepare spawning continuous send, err chan: 0x%x\n",
			s.Name, chanPtr(s.ErrCh))
		for {
			select {
			case s.IncomingChs[0] <- None{}:
				debugPrintf("[%s] source to itself None\n", s.Name)
			case err := <-errCh:
				debugPrintf("[%s] something at error channel (0x%x): %v. Stopping\n",
					s.Name, chanPtr(s.ErrCh), err)
				// Close incoming.
				close(s.IncomingChs[0])
				s.TopErrCh <- err // might block, but this goroutine is done anyways.
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
