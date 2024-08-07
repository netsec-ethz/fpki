package pipeline

type SinkLike interface {
	PrepareSink()
}
type Sink[IN any] struct {
	*Stage[IN, None]
}

var _ SinkLike = (*Sink[int])(nil)

func NewSink[IN any](
	name string,
	options ...stageOption[IN, None],
) *Sink[IN] {
	return &Sink[IN]{
		Stage: NewStage[IN, None](name, options...),
	}
}

func WithSinkFunction[IN any](
	processFunc func(in IN) error,
) stageOption[IN, None] {

	return func(s *Stage[IN, None]) {
		// Just set the process function to call the user's one.
		s.ProcessFunc = func(in IN) ([]None, []int, error) {
			err := processFunc(in)
			return nil, nil, err
		}
	}
}

func (s *Sink[IN]) PrepareSink() {
	// As a sink, our process function is already called every time there is new data.
	// But we need to keep the stage going allowing to send none{} to the outgoing channel.
	// We create a dummy channel for that.
	// This channel will be closed by the stage during processing in case of no more data,
	// error, or stop.
	// The next error channel can be closed after no more processing is done.
	s.OutgoingChs = []chan None{make(chan None)}  // Replace channels with just one.
	s.NextErrChs = []chan error{make(chan error)} // Replace channels with just one.
	go func() {
		// Block until the processing has closed the outgoing channel.
		for range s.OutgoingChs[0] {
		}
		debugPrintf("[%s] sink about to close next error channel (no more output)\n", s.Name)
		close(s.NextErrChs[0])
	}()
}

func (s *Sink[IN]) Prepare() {
	// Regular stage preparation:
	SinkAsStage(s).Prepare()

	// Prepare the sink part.
	s.PrepareSink()
}

func (s *Sink[IN]) Resume() {
	SinkAsStage(s).Resume()
}

func (s *Sink[IN]) StopAndWait() error {
	return SinkAsStage(s).StopAndWait()
}

func SinkAsStage[IN any](s *Sink[IN]) *Stage[IN, None] {
	return s.Stage
}
