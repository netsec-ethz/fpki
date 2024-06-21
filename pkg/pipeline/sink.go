package pipeline

type SinkBase[IN any] struct {
	base *Base // Reference to Base.

	// Own fields.
	IncomingCh chan IN // Incoming data channel to process.

	SinkFunc func(in IN) error
}

var _ StageLike = &SinkBase[int]{}

func NewSink[IN any]() *SinkBase[IN] {
	return nil
}

type sinkOption[IN any] func(*SinkBase[IN])

func WithSinkFunction[IN any](
	sinkFunc func(IN) error,
) sinkOption[IN] {
	return func(s *SinkBase[IN]) {
		s.SinkFunc = sinkFunc
	}
}

func (s *SinkBase[IN]) Prepare() {
	s.IncomingCh = make(chan IN)
}

func (s *SinkBase[IN]) Resume() {
	go s.sinkData()
}

func (s *SinkBase[IN]) StopAndWait() error {
	return nil
}

func (s *SinkBase[IN]) sinkData() {
	var err error
readIncoming:
	for {
		select {
		case data, ok := <-s.IncomingCh:
			if !ok {
				// Incoming channel was closed. No data to be written to outgoing channel.
				break readIncoming
			}
			err = s.SinkFunc(data)
			if err != nil {
				break readIncoming
			}
		case <-s.base.StopCh:
			return
		}
	}
	s.breakPipeline(err)
}

func (s *SinkBase[IN]) breakPipeline(errorAtSink error) {
	s.base.ErrCh <- errorAtSink
}
