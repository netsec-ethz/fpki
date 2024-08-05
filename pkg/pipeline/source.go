package pipeline

type SourceLike interface {
	Wait() error
}

type Source[OUT any] struct {
	Stage[None, OUT]
	TopErrCh chan error // This error is not propagated to other stages.
}

func NewSource[OUT any](
	name string,
	options ...stageOption[None, OUT],
) *Source[OUT] {
	s := &Source[OUT]{
		Stage: *NewStage[None, OUT](name, options...),
	}
	return s
}

func WithGeneratorFunction[OUT any](
	generator func() (OUT, int, error),
) stageOption[None, OUT] {
	return func(s *Stage[None, OUT]) {
		s.ProcessFunc = func(in None) ([]OUT, []int, error) {
			out, outChIndex, err := generator()
			return []OUT{out}, []int{outChIndex}, err
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
	// As a source, we generate data by sending none to our incoming channel,
	// until our errCh is closed.
	// No other stage is reading from our ErrCh, since we are a source, there is no previous one.
	go func() {
		for {
			select {
			case s.IncomingChs[0] <- None{}:
			case err := <-s.ErrCh:
				// Close incoming.
				close(s.IncomingChs[0])
				s.TopErrCh <- err // might block, but this goroutine is done anyways.
				return
			}
		}
	}()
}

func (s *Source[OUT]) Resume() {
	SourceAsStage(s).Resume()
}

func (s *Source[OUT]) StopAndWait() error {
	return SourceAsStage(s).StopAndWait()
}

func SourceAsStage[OUT any](s *Source[OUT]) *Stage[None, OUT] {
	return &s.Stage
}
