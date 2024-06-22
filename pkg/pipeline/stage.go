package pipeline

import (
	"bufio"
	"fmt"
	"os"
	"sync"

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

	IncomingCh  chan IN      // Incoming data channel to process.
	OutgoingChs []chan OUT   // Data to the next stages goes here.
	NextErrChs  []chan error // Next stage's error channel.

	ProcessFunc func(in IN) (OUT, int, error) // From IN to OUT, using outIndex.
}

var _ StageLike = &Stage[int, string]{}

func NewStage[IN, OUT any](
	name string,
	options ...stageOption[IN, OUT],
) *Stage[IN, OUT] {

	s := &Stage[IN, OUT]{
		Name:        name,
		OutgoingChs: make([]chan OUT, 1), // Per default, just one channel
	}
	for _, opt := range options {
		opt(s)
	}
	return s
}

type stageOption[IN, OUT any] func(*Stage[IN, OUT])

func WithProcessFunction[IN, OUT any](
	processFunc func(IN) (OUT, int, error),
) stageOption[IN, OUT] {

	return func(s *Stage[IN, OUT]) {
		s.ProcessFunc = processFunc
	}
}

func WithMultiOutputChannels[IN, OUT any](
	numberOfChannels int) stageOption[IN, OUT] {

	return func(s *Stage[IN, OUT]) {
		s.OutgoingChs = make([]chan OUT, numberOfChannels)
	}
}

// LinkStages links the possibly many outgoing channels to the incoming of the next ones.
func LinkStages[IN, OUT, LAST any](
	prev *Stage[IN, OUT],
	nextStages ...*Stage[OUT, LAST],
) {
	if len(prev.OutgoingChs) != len(nextStages) {
		panic("Incorrect number of outgoing channels and next stages")
	}
	for i, next := range nextStages {

		debugPrintf("linking [%s]:%p with [%s]:%p\n",
			prev.Name, &prev.OutgoingChs[i],
			next.Name, &next.IncomingCh,
		)
		prev.OutgoingChs[i] = next.IncomingCh
		debugPrintf("linking [%s]:%p with [%s]:%p\n",
			prev.Name, &prev.NextErrChs,
			next.Name, &next.ErrCh,
		)
		prev.NextErrChs[i] = next.ErrCh
	}
}

func (s *Stage[IN, OUT]) Prepare() {
	s.ErrCh = make(chan error)
	s.StopCh = make(chan none)
	s.IncomingCh = make(chan IN)
	s.OutgoingChs = make([]chan OUT, len(s.OutgoingChs))
	for i := range s.OutgoingChs {
		s.OutgoingChs[i] = make(chan OUT)
	}
	s.NextErrChs = make([]chan error, len(s.OutgoingChs))
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
	debugPrintf("[%s] exiting _____________________________\n", s.Name)
	debugPrintf("[%s] closing output channel %p\n", s.Name, &s.OutgoingChs)
	// time.Sleep(10 * time.Millisecond)
	// Indicate next stage to stop.
	for _, outCh := range s.OutgoingChs {
		close(outCh)
	}
	// Read its status:
	debugPrintf("[%s] waiting for next stage's error\n", s.Name)
	for _, nextErrCh := range s.NextErrChs {
		err := <-nextErrCh
		debugPrintf("[%s] read next stage's error: %v\n", s.Name, err)
		// Coalesce with any error at this stage.
		initialErr = util.ErrorsCoalesce(initialErr, err)
	}

	// Propagate error backwards.
	debugPrintf("[%s] Base: breaking pipeline\n", s.Name)
	if initialErr != nil {
		// Propagate error backwards.
		s.ErrCh <- initialErr
	}
	// Close our own error channel.
	close(s.ErrCh)
	// Close the stop channel indicator.
	close(s.StopCh)
	debugPrintf("[%s] Base: all done\n", s.Name)
	return initialErr
}

func (s *Stage[IN, OUT]) processThisStage() {
	// The aggregated channel will receive error messages from the N next stage error channels.
	nextStagesAggregatedErrCh := s.aggregateNextErrChannels()
	var foundError error
readIncoming:
	for {

		select {
		case <-s.StopCh:
			// We have been instructed to stop, without reading any other channel.
			debugPrintf("[%s] generate function indicates to stop\n", s.Name)
			return

		case err := <-nextStagesAggregatedErrCh:
			debugPrintf("[%s] got ERROR while reading incoming from next stage\n", s.Name)
			foundError = err
			break readIncoming
		case in, ok := <-s.IncomingCh:
			if !ok {
				// Incoming channel was closed. No data to be written to outgoing channel.
				debugPrintf("[%s] generate function indicates no more data\n", s.Name)
				break readIncoming
			}
			debugPrintf("[%s] incoming %v\n", s.Name, in)

			out, outChIndex, err := s.ProcessFunc(in)
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
			case s.OutgoingChs[outChIndex] <- out:
				// Success writing to the outgoing channel, nothing else to do.
				debugPrintf("[%s] sent %v\n", s.Name, out)
			case err := <-nextStagesAggregatedErrCh:
				debugPrintf("[%s] ERROR while sending at channel %d the value %v: %v\n",
					s.Name, outChIndex, out, err)
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

func (s *Stage[IN, OUT]) aggregateNextErrChannels() chan error {
	// Create an error channel to aggregate all the next stages' error channels.
	nextStagesAggregatedErrCh := make(chan error)

	// The wait group serves to know when all next stages' error channels have been closed.
	wg := sync.WaitGroup{}
	wg.Add(len(s.NextErrChs))

	// Aggregate any possible error coming from any next stage into the aggregated channel.
	for _, nextErrCh := range s.NextErrChs {
		nextErrCh := nextErrCh // Local copy for the capture of the goroutine next.
		go func() {
			defer wg.Done()
			for err := range nextErrCh {
				nextStagesAggregatedErrCh <- err
			}
			// When the nextErrCh of next stage i is closed, this goroutine signals the wg.
		}()
	}

	// Spin a goroutine to close the aggregated channel when all the next stages' ones are closed.
	go func() {
		// Wait until all nextErrCh have been closed.
		wg.Wait()
		// Now close the aggregated channel.
		close(nextStagesAggregatedErrCh)
	}()
	return nextStagesAggregatedErrCh
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
