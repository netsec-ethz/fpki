package pipeline

import (
	"github.com/netsec-ethz/fpki/pkg/util"
)

// type Source[OUT any] struct {
// 	Base
// 	SourceBase[OUT]
// }

// var _ StageLike = &Source[int]{}

// func (s *Source[OUT]) Prepare() {
// 	s.Base.Prepare()
// 	s.SourceBase.Prepare()
// }

// func (s *Source[OUT]) Resume() {
// 	s.SourceBase.Resume()
// }

// func NewSource[OUT any](
// 	name string,
// 	options ...sourceOption[OUT],
// ) *Source[OUT] {
// 	base := Base{
// 		Name: name,
// 	}
// 	return &Source[OUT]{
// 		Base:       base,
// 		SourceBase: *NewSourceBase[OUT](&base, options...),
// 	}
// }

// SourceBase is the base class of a source stage.
type SourceBase[OUT any] struct {
	base *Base // Reference to Base:

	// Own fields:
	OutgoingCh chan OUT   // Data to the next stage goes here.
	NextErrCh  chan error // Next stage's error channel.

	GenerateFunc  func() (OUT, error)
	OutChSelector func(data OUT) int // Selects which outgoing channel to use.
}

func NewSourceBase[OUT any](
	base *Base, // Reference to the one in Base.
	options ...sourceOption[OUT],
) *SourceBase[OUT] {
	s := &SourceBase[OUT]{
		base: base,
	}
	for _, opt := range options {
		opt(s)
	}
	return s
}

type sourceOption[OUT any] func(*SourceBase[OUT])

func WithGenerateFunction[OUT any](
	generateFunc func() (OUT, error),
) sourceOption[OUT] {
	return func(s *SourceBase[OUT]) {
		s.GenerateFunc = generateFunc
	}
}

func (s *SourceBase[OUT]) Prepare() {
	s.OutgoingCh = make(chan OUT)
}

func (s *SourceBase[OUT]) Resume() {
	go s.generateData()
}

func (s *SourceBase[OUT]) StopAndWait() error {
	// TODO
	return nil
}

func (s *SourceBase[OUT]) generateData() {
	var foundError error
generateData:
	for {
		out, err := s.GenerateFunc()
		switch err {
		case nil:
		case NoMoreData:
			debugPrintf("[%s] generate function indicates no more data\n", s.base.Name)
			break generateData
		case StopNoError:
			debugPrintf("[%s] generate function indicates to stop\n", s.base.Name)
			return
		default:
			// Stop processing pipeline.
			debugPrintf("[%s] received error from generate function: %s\n", s.base.Name, err)
			foundError = err
			break generateData
		}

		// We attempt to write the out data to the outgoing channel.
		// Because this can block, we must also listen to any error coming from the
		// next stage, plus our own stop signal.
		debugPrintf("[%s] attempting to send %v\n", s.base.Name, out)
		select {
		case s.OutgoingCh <- out:
			// Success writing to the outgoing channel, nothing else to do.
			debugPrintf("[%s] sent %v\n", s.base.Name, out)
		case err := <-s.NextErrCh:
			debugPrintf("[%s] ERROR while sending %v: %s\n", s.base.Name, out, err)
			// We received an error from next stage while trying to write to it.
			foundError = err
			break generateData
		case <-s.base.StopCh:
			// We have been instructed to stop, without reading any other channel.
			debugPrintf("[%s] instructed to stop\n", s.base.Name)
			return
		}
	}
	s.breakPipelineAndWait(foundError)
}

func (s *SourceBase[OUT]) breakPipelineAndWait(initialErr error) error {
	debugPrintf("[%s] closing output channel\n", s.base.Name)
	// Indicate next stage to stop.
	close(s.OutgoingCh)
	// Read its status:
	debugPrintf("[%s] waiting for next stage's error\n", s.base.Name)
	err := <-s.NextErrCh
	debugPrintf("[%s] read next stage's error: %v\n", s.base.Name, err)
	// Coalesce with any error at this stage.
	err = util.ErrorsCoalesce(initialErr, err)

	s.base.breakPipeline(initialErr)
	return err
}
