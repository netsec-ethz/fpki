package pipeline

type SourceLike interface {
	Wait() error
}

type Source[OUT any] struct {
	Stage[none, OUT]
	TopErrCh chan error // This error is not propagated to other stages.
}

func NewSource[OUT any](
	name string,
	options ...stageOption[none, OUT],
) *Source[OUT] {
	return &Source[OUT]{
		Stage: *NewStage[none, OUT](name, options...),
	}
}

func WithGeneratorFunction[OUT any](
	generator func() (OUT, int, error),
) stageOption[none, OUT] {
	return func(s *Stage[none, OUT]) {
		s.ProcessFunc = func(in none) (OUT, int, error) {
			out, outChIndex, err := generator()
			return out, outChIndex, err
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
			case s.IncomingCh <- none{}:
			case err := <-s.ErrCh:
				// Close incoming.
				close(s.IncomingCh)
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

func SourceAsStage[OUT any](s *Source[OUT]) *Stage[none, OUT] {
	return &s.Stage
}
