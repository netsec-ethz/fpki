package pipeline

import "context"

type SinkLike interface {
	StageLike
	PrepareSink(context.Context)
}

func IsSink(s StageLike) bool {
	_, ok := s.(SinkLike)
	return ok
}

type Sink[IN any] struct {
	*Stage[IN, None]
}

var _ SinkLike = (*Sink[int])(nil)

func NewSink[IN any](
	name string,
	options ...option[IN, None],
) *Sink[IN] {
	s := &Sink[IN]{
		Stage: NewStage[IN, None](name, options...),
	}

	for _, opt := range options {
		opt.ApplyToSink(s)
	}

	return s
}

func WithSinkFunction[IN any](
	processFunc func(in IN) error,
) option[IN, None] {
	return newSinkOption(func(s *Sink[IN]) {
		// Just set the process function to call the user's one.
		s.ProcessFunc = func(in IN) ([]None, []int, error) {
			err := processFunc(in)
			return nil, nil, err
		}
	})
}

func (s *Sink[IN]) PrepareSink(ctx context.Context) {
	// As a sink, our process function is already called every time there is new data.
	// But we need to keep the stage going allowing to send none{} to the outgoing channel.
	// We create a dummy channel for that.
	// This channel will be closed by the stage during processing in case of no more data,
	// error, or stop.
	// The next error channel can be closed after no more processing is done.
	s.OutgoingChs = []chan None{make(chan None)}  // Replace channels with just one.
	s.NextErrChs = []chan error{make(chan error)} // Replace channels with just one.
	go func(outCh chan None, errCh chan error) {
		// Block until the processing has closed the outgoing channel.
		for range outCh {
		}
		DebugPrintf("[%s] sink: output %s is closed: closing next error channel [0] %s\n",
			s.Name, chanPtr(s.OutgoingChs[0]), chanPtr(errCh))
		close(errCh)
	}(s.OutgoingChs[0], s.NextErrChs[0])
}

func (s *Sink[IN]) Prepare(ctx context.Context) {
	// Regular stage preparation:
	SinkAsStage(s).Prepare(ctx)

	// Prepare the sink part.
	s.PrepareSink(ctx)
}

func SinkAsStage[IN any](s *Sink[IN]) *Stage[IN, None] {
	return s.Stage
}
