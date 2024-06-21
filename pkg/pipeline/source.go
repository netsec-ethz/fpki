package pipeline

type Source[OUT any] struct {
	Name       string
	OutgoingCh *chan OUT

	ErrCh *chan error

	GenerateFunc func() (OUT, error)
}

var _ StageLike = &Source[int]{}

func NewSource[OUT any](
	name string,
	options ...sourceOptions[OUT],
) {

}

type sourceOptions[OUT any] func(*Source[OUT])

func WithGenerateFunction[OUT any](
	generateFunc func() (OUT, error),
) sourceOptions[OUT] {
	return func(s *Source[OUT]) {
		s.GenerateFunc = generateFunc
	}
}

func (s *Source[OUT]) Resume() {
	*s.ErrCh = make(chan error)
	go s.generateData()
}

func (s *Source[OUT]) StopAndWait() error {
	return nil
}

func (s *Source[OUT]) generateData() {
	for {
		d, err := s.GenerateFunc()
		if err == NoMoreData {
			break
		}
		if err != nil {
			// Stop processing pipeline.
			close(*s.OutgoingCh)
		}
		*s.OutgoingCh <- d
	}
}

type noMoreDataError struct{}

func (noMoreDataError) Error() string { return "" }

var NoMoreData = noMoreDataError{}
