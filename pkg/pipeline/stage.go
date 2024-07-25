package pipeline

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/netsec-ethz/fpki/pkg/util"
)

type StageLike interface {
	Prepare()
	Resume()
	StopAndWait() error
	ErrorChannel() chan error
	IncomingChanCount() int
	OutgoingChanCount() int
}

type Stage[IN, OUT any] struct {
	Name   string     // Name of the stage.
	ErrCh  chan error // To be read by the previous stage (or trigger, if this is Source).
	StopCh chan None  // Indicates to this stage to stop.

	IncomingChs               []chan IN    // Incoming data channel to process.
	OutgoingChs               []chan OUT   // Data to the next stages goes here.
	NextErrChs                []chan error // Next stage's error channel.
	NextStagesAggregatedErrCh chan error   // Aggregated nexErrChs

	ProcessFunc func(in IN) ([]OUT, []int, error) // From 1 IN to n OUT, using n channels.
	// Before stopping the pipeline. This function allows processing before stopping the pipeline.
	onNoMoreData func() ([]OUT, []int, error)
}

var _ StageLike = &Stage[int, string]{}

func NewStage[IN, OUT any](
	name string,
	options ...stageOption[IN, OUT],
) *Stage[IN, OUT] {

	s := &Stage[IN, OUT]{
		Name:        name,
		IncomingChs: make([]chan IN, 1),  // Per default, just one channel.
		OutgoingChs: make([]chan OUT, 1), // Per default, just one channel.
		onNoMoreData: func() ([]OUT, []int, error) { // Noop.
			return nil, nil, nil
		},
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
		s.ProcessFunc = func(in IN) ([]OUT, []int, error) {
			out, ix, err := processFunc(in)
			return []OUT{out}, []int{ix}, err
		}
	}
}

// WithProcessFunctionMultipleOutputs allows the stage to create multiple outputs per given input.
// The outputs are sent to the next stage _with no order_.
func WithProcessFunctionMultipleOutputs[IN, OUT any](
	processFunc func(IN) ([]OUT, []int, error),
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

func WithMultiInputChannels[IN, OUT any](
	numberOfChannels int) stageOption[IN, OUT] {

	return func(s *Stage[IN, OUT]) {
		s.IncomingChs = make([]chan IN, numberOfChannels)
	}
}

// WithOnNoMoreData acts as WithProcessFunctionMultipleOutputs, but it is called without any input,
// when this stage has detected no more incoming data.
// The outputs are sent to the next stage _in no particular order_.
func WithOnNoMoreData[IN, OUT any](
	handler func() ([]OUT, []int, error),
) stageOption[IN, OUT] {
	return func(s *Stage[IN, OUT]) {
		s.onNoMoreData = handler
	}
}

// LinkStagesAt links an outgoing channel of a stage to an incoming one of another.
func LinkStagesAt[IN, OUT, LAST any](
	prev *Stage[IN, OUT],
	outIndex int,
	next *Stage[OUT, LAST],
	inIndex int,
) {
	debugPrintf("linking [%s]:%p with [%s]:%p\n",
		prev.Name, &prev.OutgoingChs[outIndex],
		next.Name, &next.IncomingChs[inIndex],
	)
	prev.OutgoingChs[outIndex] = next.IncomingChs[inIndex]
	debugPrintf("linking [%s]:%p with [%s]:%p\n",
		prev.Name, &prev.NextErrChs,
		next.Name, &next.ErrCh,
	)
	prev.NextErrChs[outIndex] = next.ErrCh
}

// LinkStagesFanOut connects the multiple output channels of a stage to the next stages.
// The next stages channel index 0 is always used.
func LinkStagesFanOut[IN, OUT, LAST any](
	prev *Stage[IN, OUT],
	nextStages ...*Stage[OUT, LAST],
) {
	if len(prev.OutgoingChs) != len(nextStages) {
		panic("Incorrect number of outgoing channels and next stages")
	}
	for i, next := range nextStages {
		LinkStagesAt(prev, i, next, 0)
	}
}

func (s *Stage[IN, OUT]) IncomingChanCount() int {
	return len(s.IncomingChs)
}

func (s *Stage[IN, OUT]) OutgoingChanCount() int {
	return len(s.OutgoingChs)
}

func (s *Stage[IN, OUT]) Prepare() {
	s.ErrCh = make(chan error)
	s.StopCh = make(chan None)

	for i := range s.IncomingChs {
		s.IncomingChs[i] = make(chan IN)
	}
	for i := range s.OutgoingChs {
		s.OutgoingChs[i] = make(chan OUT)
	}
	s.NextErrChs = make([]chan error, len(s.OutgoingChs))

	// Cannot aggregate the error channels here, as they will be inserted after linking.
}

// Resume resumes processing from this stage.
// This function creates new channels for the incoming data, error and stop channels.
func (s *Stage[IN, OUT]) Resume() {
	// The aggregated channel will receive error messages from the N next stage error channels.
	// All the nextStageErrCh are created and ready at this point.
	s.NextStagesAggregatedErrCh = s.aggregateNextErrChannels()
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
	s.StopCh <- None{}

	return s.breakPipelineAndWait(nil)
}

func (s *Stage[IN, OUT]) ErrorChannel() chan error {
	return s.ErrCh
}

func (s *Stage[IN, OUT]) breakPipelineAndWait(initialErr error) error {
	debugPrintf("[%s] exiting _____________________________ err=%v\n", s.Name, initialErr)
	debugPrintf("[%s] closing output channel %p\n", s.Name, &s.OutgoingChs)
	// time.Sleep(10 * time.Millisecond)
	// Indicate next stage to stop.
	for _, outCh := range s.OutgoingChs {
		close(outCh)
	}
	// Read its status:
	debugPrintf("[%s] waiting for next stage's error\n", s.Name)
	err := <-s.NextStagesAggregatedErrCh
	debugPrintf("[%s] read next stage's error: %v\n", s.Name, err)
	// Coalesce with any error at this stage.
	initialErr = util.ErrorsCoalesce(initialErr, err)

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
	// The aggregated channel will receive all incoming data.
	aggregatedIncomeCh := s.aggregateIncomingChannels()
	var foundError error
readIncoming:
	for {
		select {
		case <-s.StopCh:
			// We have been instructed to stop, without reading any other channel.
			debugPrintf("[%s] generate function indicates to stop\n", s.Name)
			return

		case err := <-s.NextStagesAggregatedErrCh:
			debugPrintf("[%s] got ERROR while reading incoming from next stage\n", s.Name)
			foundError = err
			break readIncoming
		case in, ok := <-aggregatedIncomeCh:
			debugPrintf("[%s] incoming? %v, data: %v\n", s.Name, ok, in)

			var shouldBreakReadingIncoming bool
			var shouldReturn bool

			var outs []OUT
			var outChIndxs []int
			var err error
			if !ok {
				// Incoming channel was closed. No data to be written to outgoing channel.
				debugPrintf("[%s] generate function indicates no more data\n", s.Name)
				outs, outChIndxs, err = s.onNoMoreData()
				shouldBreakReadingIncoming = true // Regardless of err, request to break.
			} else {
				outs, outChIndxs, err = s.ProcessFunc(in)
			}

			switch err {
			case nil:
			case NoMoreData:
				// No more data, no error.
				// Flag the about-to-stop pipeline event and use its error.
				debugPrintf("[%s] about to call OnNoMoreData\n", s.Name)
				outs, outChIndxs, foundError = s.onNoMoreData()
				// Break out of the reading loop, after processing output.
				shouldBreakReadingIncoming = true
			default:
				// Processing failed, break immediately.
				foundError = err
				break readIncoming
			}

			// For each output spawn a go routine sending it to the appropriate channel.
			wg := sync.WaitGroup{}
			wg.Add(len(outs))

			for i := range outs {
				i := i
				go func() {
					defer wg.Done()
					out := outs[i]
					outChIndex := outChIndxs[i]
					// We attempt to write the out data to the outgoing channel.
					// Because this can block, we must also listen to any error coming from the
					// next stage, plus our own stop signal.
					debugPrintf("[%s] attempting to send %v\n", s.Name, out)
					select {
					case s.OutgoingChs[outChIndex] <- out:
						// Success writing to the outgoing channel, nothing else to do.
						debugPrintf("[%s] sent %v\n", s.Name, out)
					case err := <-s.NextStagesAggregatedErrCh:
						debugPrintf("[%s] ERROR while sending at channel %d the value %v: %v\n",
							s.Name, outChIndex, out, err)
						// We received an error from next stage while trying to write to it.
						foundError = err
						shouldBreakReadingIncoming = true
					case <-s.StopCh:
						// We have been instructed to stop, without reading any other channel.
						debugPrintf("[%s] instructed to stop\n", s.Name)
						shouldReturn = true
					}
				}()
			}
			// Wait for all outputs to be sent.
			wg.Wait()
			// Determine the next action to do.
			if shouldReturn {
				return
			}
			if shouldBreakReadingIncoming {
				break readIncoming
			}
		} // end of select
	} // end-for infinite loop with label readIncoming.

	// Stop pipeline.
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

func (s *Stage[IN, OUT]) aggregateIncomingChannels() chan IN {
	// Create a new channel to aggregate all the incoming data from different channels.
	aggregated := make(chan IN)

	// The wait group serves to know when all incoming channels have been closed.
	wg := sync.WaitGroup{}
	wg.Add(len(s.IncomingChs))

	// Aggregate any possible incoming data into the aggregated channel.
	for _, incomingCh := range s.IncomingChs {
		incomingCh := incomingCh // Local copy for the capture of the goroutine next.
		go func() {
			defer wg.Done()
			for in := range incomingCh {
				aggregated <- in
			}
			// When the incomingCh number i is closed, signal the wait group.
		}()
	}

	// Spin a goroutine to close the aggregated channel when all the incoming ones are closed.
	go func() {
		// Wait until all incomingCh have been closed.
		wg.Wait()
		// Now close the aggregated channel.
		close(aggregated)
	}()
	return aggregated
}

type None struct{}

type noError struct{}

func (noError) Error() string { return "" }

var NoMoreData = noError{}

type debugLine struct {
	Time time.Time
	Line string
}

var debugLines []debugLine
var debugLinesMu sync.Mutex

func debugPrintf(format string, args ...any) {
	t := time.Now()
	line := fmt.Sprintf(format, args...)
	debugLinesMu.Lock()
	defer debugLinesMu.Unlock()
	debugLines = append(debugLines, debugLine{
		Time: t,
		Line: line,
	})
}

func printAllDebugLines() {
	sort.Slice(debugLines, func(i, j int) bool {
		return debugLines[i].Time.Before(debugLines[j].Time)
	})
	for i, d := range debugLines {
		fmt.Printf("[%3d] [%30s] %s",
			i,
			d.Time.Format(time.StampNano),
			d.Line,
		)
	}
}
