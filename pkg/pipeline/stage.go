package pipeline

import (
	"bufio"
	"fmt"
	"os"

	"github.com/netsec-ethz/fpki/pkg/util"
)

type StageLike interface {
	Prepare()
	Resume()
	StopAndWait() error
	ErrorChannel() chan error
}

type Stage[IN, OUT any] struct {
	Name   string     // Name of the stage.
	ErrCh  chan error // To be read by the previous stage (or trigger, if this is Source).
	StopCh chan none  // Indicates to this stage to stop.

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

	s := &Stage[IN, OUT]{
		Name: name,
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
	s.ErrCh = make(chan error)
	s.StopCh = make(chan none)
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
	s.StopCh <- none{}

	return s.breakPipelineAndWait(nil)
}

func (s *Stage[IN, OUT]) ErrorChannel() chan error {
	return s.ErrCh
}

func (s *Stage[IN, OUT]) breakPipelineAndWait(initialErr error) error {
	debugPrintf("[%s] closing output channel %p\n", s.Name, &s.OutgoingCh)
	// time.Sleep(10 * time.Millisecond)
	// Indicate next stage to stop.
	close(s.OutgoingCh)
	// Read its status:
	debugPrintf("[%s] waiting for next stage's error\n", s.Name)
	err := <-s.NextErrCh
	debugPrintf("[%s] read next stage's error: %v\n", s.Name, err)
	// Coalesce with any error at this stage.
	err = util.ErrorsCoalesce(initialErr, err)

	// Propagate error backwards.
	debugPrintf("[%s] Base: breaking pipeline\n", s.Name)
	if err != nil {
		// Propagate error backwards.
		s.ErrCh <- err
	}
	// Close our own error channel.
	close(s.ErrCh)
	// Close the stop channel indicator.
	close(s.StopCh)
	debugPrintf("[%s] Base: all done\n", s.Name)
	return err
}

func (s *Stage[IN, OUT]) processThisStage() {
	var foundError error
readIncoming:
	for {

		select {
		case <-s.StopCh:
			// We have been instructed to stop, without reading any other channel.
			debugPrintf("[%s] generate function indicates to stop\n", s.Name)
			return

		case err := <-s.NextErrCh:
			debugPrintf("[%s] got error while reading incoming from next stage\n", s.Name)
			foundError = err
			break readIncoming
		case in, ok := <-s.IncomingCh:
			if !ok {
				// Incoming channel was closed. No data to be written to outgoing channel.
				debugPrintf("[%s] generate function indicates no more data\n", s.Name)
				break readIncoming
			}
			debugPrintf("[%s] incoming %v\n", s.Name, in)

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
			debugPrintf("[%s] attempting to send %v\n", s.Name, out)
			select {
			case s.OutgoingCh <- out:
				// Success writing to the outgoing channel, nothing else to do.
				debugPrintf("[%s] sent %v\n", s.Name, out)
			case err := <-s.NextErrCh:
				debugPrintf("[%s] ERROR while sending %v: %s\n", s.Name, out, err)
				// We received an error from next stage while trying to write to it.
				foundError = err
				break readIncoming
			case <-s.StopCh:
				// We have been instructed to stop, without reading any other channel.
				debugPrintf("[%s] instructed to stop\n", s.Name)
				return
			}
		}
	}
	s.breakPipelineAndWait(foundError)
}

func debugPrintf(format string, args ...any) {
	var stdout = bufio.NewWriter(os.Stdout)
	fmt.Fprintf(stdout, format, args...)
	if err := stdout.Flush(); err != nil {
		panic(err)
	}
	// fmt.Printf(format, args...)
}

type none struct{}

type noError struct{}

func (noError) Error() string { return "" }

var NoMoreData = noError{}

// var sentNoError = noError{}
// var stopNoError = noError{}
