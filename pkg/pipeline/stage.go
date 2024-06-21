package pipeline

import (
	"github.com/netsec-ethz/fpki/pkg/util"
)

type StageLike interface {
	Prepare()
	Resume()
	StopAndWait() error
	ErrorChannel() chan error
}

type Stage[IN, OUT any] struct {
	*Base // Common fields.

	IncomingCh chan IN    // Incoming data channel to process.
	OutgoingCh chan OUT   // Data to the next stage goes here.
	NextErrCh  chan error // Next stage's error channel.

	ProcessFunc func(in IN) (OUT, error) // From IN to OUT.
}

var _ StageLike = &Stage[int, string]{}

func NewStage[IN, OUT any](
	name string,
	options ...stageOption[IN, OUT],
) *Stage[IN, OUT] {

	base := NewBase(name)
	s := &Stage[IN, OUT]{
		Base: base,
	}
	for _, opt := range options {
		opt(s)
	}
	return s
}

type stageOption[IN, OUT any] func(*Stage[IN, OUT])

func WithProcessFunction[IN, OUT any](
	processFunc func(IN) (OUT, error),
) stageOption[IN, OUT] {
	return func(s *Stage[IN, OUT]) {
		s.ProcessFunc = processFunc
	}
}

func LinkStages[IN, OUT, LAST any](
	prev *Stage[IN, OUT],
	next *Stage[OUT, LAST],
) {
	debugPrintf("linking [%s]:%p with [%s]:%p\n",
		prev.Name, &prev.OutgoingCh,
		next.Name, &next.IncomingCh,
	)
	prev.OutgoingCh = next.IncomingCh
	debugPrintf("linking [%s]:%p with [%s]:%p\n",
		prev.Name, &prev.NextErrCh,
		next.Name, &next.ErrCh,
	)
	prev.NextErrCh = next.ErrCh
}

func (s *Stage[IN, OUT]) Prepare() {
	s.Base.Prepare()
	s.IncomingCh = make(chan IN)
	s.OutgoingCh = make(chan OUT)
}

// Resume resumes processing from this stage.
// This function creates new channels for the incoming data, error and stop channels.
func (s *Stage[IN, OUT]) Resume() {
	go s.processThisStage()
}

// StopAndWait stops this and following stages by closing this stage's outgoing channel.
// This stage's outgoing channel is the same as the next stage's incoming channel.
// This function waits for the next stage to finish and returns any error.
func (s *Stage[IN, OUT]) StopAndWait() error {
	// Stop listening on other goroutines from the next stage's error channel.
	// Also stop sending data to the outgoing channel. This means effectively, stop the
	// working resume goroutine. We explicitly indicate the goroutine to finish and
	// not to read any state from the next stage. We will do that here.
	s.Base.StopCh <- none{}

	return s.breakPipelineAndWait(nil)
}

func (s *Stage[IN, OUT]) ErrorChannel() chan error {
	return s.Base.ErrCh
}

func (s *Stage[IN, OUT]) breakPipelineAndWait(initialErr error) error {
	debugPrintf("[%s] closing output channel %p\n", s.Base.Name, &s.OutgoingCh)
	// time.Sleep(10 * time.Millisecond)
	// Indicate next stage to stop.
	close(s.OutgoingCh)
	// Read its status:
	debugPrintf("[%s] waiting for next stage's error\n", s.Base.Name)
	err := <-s.NextErrCh
	debugPrintf("[%s] read next stage's error: %v\n", s.Base.Name, err)
	// Coalesce with any error at this stage.
	err = util.ErrorsCoalesce(initialErr, err)

	// Propagate error backwards.
	s.Base.breakPipeline(err)
	return err
}

func (s *Stage[IN, OUT]) processThisStage() {
	var foundError error
readIncoming:
	for {

		select {
		case <-s.StopCh:
			// We have been instructed to stop, without reading any other channel.
			debugPrintf("[%s] generate function indicates to stop\n", s.Base.Name)
			return

		case err := <-s.NextErrCh:
			debugPrintf("[%s] got error while reading incoming from next stage\n", s.Name)
			foundError = err
			break readIncoming
		case in, ok := <-s.IncomingCh:
			if !ok {
				// Incoming channel was closed. No data to be written to outgoing channel.
				debugPrintf("[%s] generate function indicates no more data\n", s.Base.Name)
				break readIncoming
			}
			debugPrintf("[%s] incoming %v\n", s.Base.Name, in)

			out, err := s.ProcessFunc(in)
			if err == NoMoreData {
				// No more data, no error.
				break readIncoming
			}
			if err != nil {
				// Processing failed.
				foundError = err
				break readIncoming
			}
			// We attempt to write the out data to the outgoing channel.
			// Because this can block, we must also listen to any error coming from the
			// next stage, plus our own stop signal.
			debugPrintf("[%s] attempting to send %v\n", s.Base.Name, out)
			select {
			case s.OutgoingCh <- out:
				// Success writing to the outgoing channel, nothing else to do.
				debugPrintf("[%s] sent %v\n", s.Base.Name, out)
			case err := <-s.NextErrCh:
				debugPrintf("[%s] ERROR while sending %v: %s\n", s.Base.Name, out, err)
				// We received an error from next stage while trying to write to it.
				foundError = err
				break readIncoming
			case <-s.Base.StopCh:
				// We have been instructed to stop, without reading any other channel.
				debugPrintf("[%s] instructed to stop\n", s.Base.Name)
				return
			}
		}
	}
	s.breakPipelineAndWait(foundError)
}
