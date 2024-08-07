package pipeline

import (
	"fmt"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/netsec-ethz/fpki/pkg/util"
)

type StageLike interface {
	Prepare()
	Resume()
	Base() *StageBase
}

type StageBase struct {
	Name   string     // Name of the stage.
	ErrCh  chan error // To be read by the previous stage (or trigger, if this is Source).
	StopCh chan None  // Indicates to this stage to stop.
}

func (s *StageBase) Base() *StageBase {
	return s
}

type Stage[IN, OUT any] struct {
	StageBase
	IncomingChs                   []chan IN    // Incoming data channel to process.
	OutgoingChs                   []chan OUT   // Data to the next stages goes here.
	NextErrChs                    []chan error // Next stage's error channel.
	NextStagesAggregatedErrCh     chan error   // Aggregated nexErrChs
	cacheCompletedOutgoingIndices []int        // Cache to reuse space.

	ProcessFunc func(in IN) ([]OUT, []int, error) // From 1 IN to n OUT, using n channels.
	// Before stopping the pipeline. This function allows processing before stopping the pipeline.
	onNoMoreData func() ([]OUT, []int, error)

	buildAggregatedInput func() chan IN                           // Alter by With* modifier.
	sendOutputs          func([]OUT, []int, *bool, *bool, *error) // Selectable by With* modifier.
}

var _ StageLike = &Stage[int, string]{}

func NewStage[IN, OUT any](
	name string,
	options ...stageOption[IN, OUT],
) *Stage[IN, OUT] {

	s := &Stage[IN, OUT]{
		StageBase: StageBase{
			Name: name,
		},
		IncomingChs:                   make([]chan IN, 1),  // Per default, just one channel.
		OutgoingChs:                   make([]chan OUT, 1), // Per default, just one channel.
		cacheCompletedOutgoingIndices: make([]int, 0, 16),  // Init to 16 outputs per process call.
		onNoMoreData: func() ([]OUT, []int, error) { // Noop.
			return nil, nil, nil
		},
	}
	s.buildAggregatedInput = s.readIncomingConcurrently
	s.sendOutputs = s.sendOutputsSequential

	for _, opt := range options {
		opt(s)
	}

	return s
}

type stageOption[IN, OUT any] func(*Stage[IN, OUT])

// WithProcessFunction allows the stage to create multiple outputs per given input.
// The outputs are sent to the next stage _with no order_.
func WithProcessFunction[IN, OUT any](
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

// WithConcurrentInputs sets the input channels reading logic to spawn one goroutine per channel,
// allowing any incoming message to be passed to the stage, and not keeping any order.
// This is the default.
func WithConcurrentInputs[IN, OUT any]() stageOption[IN, OUT] {
	return func(s *Stage[IN, OUT]) {
		s.buildAggregatedInput = s.readIncomingConcurrently
	}
}

// WithSequentialInputs changes the reading logic of the stage to always read its incoming channels
// in index order, starting with 0 and wrapping around len(s.IncomingChs).
// This means that if channel i-1 is blocked, the stage won't read channel i until that one is
// either unblocked, closed, or the stop signal for this stage is called.
func WithSequentialInputs[IN, OUT any]() stageOption[IN, OUT] {
	return func(s *Stage[IN, OUT]) {
		s.buildAggregatedInput = s.readIncomingSequentially
	}
}

// WithCyclesAllowedSequentialOutputs sends the output on each output channel without allocating
// memory, and not blocking, at the expense of a higher CPU cost for this stage, as it continuously
// spins checking if the output channels are ready.
// This is the default.
func WithCyclesAllowedSequentialOutputs[IN, OUT any]() stageOption[IN, OUT] {
	return func(s *Stage[IN, OUT]) {
		s.sendOutputs = s.sendOutputsCyclesAllowed
	}
}

// WithConcurrentOutputs changes the default sending logic to use a goroutine per output.
// This allows for an unordered, non-blocking delivery of the outputs to the next stages,
// at the expense of some allocations being made.
func WithConcurrentOutputs[IN, OUT any]() stageOption[IN, OUT] {
	return func(s *Stage[IN, OUT]) {
		s.sendOutputs = s.sendOutputConcurrent
	}
}

// WithSequentialOutputs changes the sending logic to the sequential propagation, which is the
// simplest one, but does not allow cycles in the stage connection graph.
// The sequential propagation is the cheapest method in terms of CPU consumption, but can reduce
// concurrency if few stages in a layer are receiving most of the data.
func WithSequentialOutputs[IN, OUT any]() stageOption[IN, OUT] {
	return func(s *Stage[IN, OUT]) {
		s.sendOutputs = s.sendOutputsSequential
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

	// Cannot aggregate the error channels here, as they will be inserted after linking with
	// other stages.
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

// breakPipelineAndWait closes the outgoing channels in index order, and stops to read the
// next stages' error channels, in whichever order (no sorting of the error channels).
func (s *Stage[IN, OUT]) breakPipelineAndWait(initialErr error) error {
	debugPrintf("[%s] exiting _____________________________ initial err=%v\n", s.Name, initialErr)

	// Indicate next stage to stop.
	for i, outCh := range s.OutgoingChs {
		debugPrintf("[%s] closing output channel index %d\n", s.Name, i)
		close(outCh)
	}

	// Read its status:
	debugPrintf("[%s] waiting for next stage's error\n", s.Name)
	err := <-s.NextStagesAggregatedErrCh
	debugPrintf("[%s] read next stage's error: %v\n", s.Name, err)

	// Coalesce with any error at this stage.
	initialErr = util.ErrorsCoalesce(initialErr, err)

	// Propagate error backwards.
	debugPrintf("[%s] closing error channel, previous stage will be notified\n", s.Name)
	if initialErr != nil {
		// Propagate error backwards.
		s.ErrCh <- initialErr
	}

	// Close our own error channel.
	close(s.ErrCh)

	// Close the stop channel indicator.
	close(s.StopCh)
	debugPrintf("[%s] all done, stage is stopped\n", s.Name)
	return initialErr
}

func (s *Stage[IN, OUT]) processThisStage() {
	// The aggregated channel will receive all incoming data.
	aggregatedIncomeCh := s.aggregateIncomingChannels()

	var foundError error
	var shouldReturn bool
	var shouldBreakReadingIncoming bool

readIncoming:
	for {
		select {
		case <-s.StopCh:
			// We have been instructed to stop, without reading any other channel.
			debugPrintf("[%s] stop requested\n", s.Name)
			return

		case err := <-s.NextStagesAggregatedErrCh:
			debugPrintf("[%s] got ERROR while reading incoming from next stage\n", s.Name)
			foundError = err
			break readIncoming

		case in, ok := <-aggregatedIncomeCh:
			debugPrintf("[%s] incoming? %v\n", s.Name, ok)
			// debugPrintf("[%s] incoming value = %v\n", s.Name, in)

			var outs []OUT
			var outChIndxs []int
			var err error
			if !ok {
				// Incoming channel was closed. No data to be written to outgoing channel.
				debugPrintf("[%s] input indicates no more data\n", s.Name)
				outs, outChIndxs, err = s.onNoMoreData()
				shouldBreakReadingIncoming = true // Regardless of err, request to break.
			} else {
				outs, outChIndxs, err = s.ProcessFunc(in)
			}

			switch err {
			case nil: // do nothing
			case NoMoreData:
				// No more data, no error.
				// Break out of the reading loop, after processing (possibly empty) output.
				shouldBreakReadingIncoming = true
			default:
				// Processing failed, break immediately.
				foundError = err
				break readIncoming
			}

			// We have multiple outputs to multiple channels.
			s.sendOutputs(
				outs,
				outChIndxs,
				&shouldReturn,
				&shouldBreakReadingIncoming,
				&foundError,
			)

			// Determine the next action to do.
			if shouldReturn {
				return
			}
			if shouldBreakReadingIncoming {
				break readIncoming
			}
		} // end of select
	} // end of for-loop readIncoming

	// Stop pipeline.
	s.breakPipelineAndWait(foundError)
}

// sendOutputsSequential sends the outputs to their channels, one by one, and blocking at each one.
// This would prevent correct functioning (deadlock) when cycles exist in the stage graph:
// E.g. if the output at this stage is blocked, and the next stage's output is blocked from this stage
// not reading from its input.
func (s *Stage[IN, OUT]) sendOutputsSequential(
	outs []OUT,
	outChIndxs []int,
	shouldReturn *bool,
	shouldBreakReadingIncoming *bool,
	foundError *error,
) {
	for i := range outs {
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
			debugPrintf("[%s] ERROR while sending at channel %d the value %v, error: %v\n",
				s.Name, outChIndex, out, err)
			// We received an error from next stage while trying to write to it.
			*foundError = err
			*shouldBreakReadingIncoming = true
		case <-s.StopCh:
			// We have been instructed to stop, without reading any other channel.
			debugPrintf("[%s] instructed to stop\n", s.Name)
			*shouldReturn = true
		}
	}
}

// sendOutputConcurrent sends the possibly multiple outputs to each out channel concurrently.
func (s *Stage[IN, OUT]) sendOutputConcurrent(
	outs []OUT,
	outChIndxs []int,
	shouldReturn *bool,
	shouldBreakReadingIncoming *bool,
	foundError *error,
) {
	// For each output spawn a go routine sending it to the appropriate channel.
	wg := sync.WaitGroup{}
	wg.Add(len(outs))

	for i := range outs {
		i := i
		go func() {
			out := outs[i]
			outChIndex := outChIndxs[i]

			defer wg.Done()
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
				*foundError = err
				*shouldBreakReadingIncoming = true
			case <-s.StopCh:
				// We have been instructed to stop, without reading any other channel.
				debugPrintf("[%s] instructed to stop\n", s.Name)
				*shouldReturn = true
			}
		}()
	}
	// Wait for all outputs to be sent.
	wg.Wait()
}

// sendOutputsCyclesAllowed sends the output to each of the output channels, in a single
// goroutine, trying to send on each channel without blocking.
// This function allows the stages to conform a graph with cycles in it.
func (s *Stage[IN, OUT]) sendOutputsCyclesAllowed(
	outs []OUT,
	outChIndxs []int,
	shouldReturn *bool,
	shouldBreakReadingIncoming *bool,
	foundError *error,
) {
	// For each value/channel, try to send if it doesn't block, otherwise bail and go to
	// the next value/channel.
	shouldStopSending := false
	for {
		s.cacheCompletedOutgoingIndices = s.cacheCompletedOutgoingIndices[:0]
	eachOutput:
		for i := range outs {
			out := outs[i]
			outChIndex := outChIndxs[i]
			// We attempt to write the out data to the outgoing channel.
			// Because this can block, we must also listen to any error coming from the
			// next stage, plus our own stop signal.
			debugPrintf("[%s] attempting to send to channel %d\n", s.Name, outChIndex)
			select {
			case s.OutgoingChs[outChIndex] <- out:
				// Success writing to the outgoing channel, nothing else to do.
				s.cacheCompletedOutgoingIndices = append(s.cacheCompletedOutgoingIndices, i)
				debugPrintf("[%s] sent to channel %d\n", s.Name, outChIndex)
			case err := <-s.NextStagesAggregatedErrCh:
				debugPrintf("[%s] ERROR while sending at channel %d the value %v: %v\n",
					s.Name, outChIndex, out, err)
				// We received an error from next stage while trying to write to it.
				*foundError = err
				shouldStopSending = true
				break eachOutput
			case <-s.StopCh:
				// We have been instructed to stop, without reading any other channel.
				debugPrintf("[%s] instructed to stop\n", s.Name)
				*shouldReturn = true
			default: // the outCh is not ready, try with next value/channel
				debugPrintf("[%s] out channel %d not ready\n", s.Name, outChIndex)
			}
		}
		util.RemoveElementsFromSlice(&outs, s.cacheCompletedOutgoingIndices)
		util.RemoveElementsFromSlice(&outChIndxs, s.cacheCompletedOutgoingIndices)
		if len(outs) == 0 || *shouldReturn || shouldStopSending {
			debugPrintf("[%s] break sending: len(outs) = %d, shouldReturn = %v, shouldBreak = %v\n",
				s.Name, len(outs), *shouldReturn, *shouldBreakReadingIncoming)
			break
		}
		runtime.Gosched() // Yield processor before we attempt to send again.
	}

	// Aggregate the stop-sending-flag to also stop reading.
	*shouldBreakReadingIncoming = *shouldBreakReadingIncoming || shouldStopSending
}

func (s *Stage[IN, OUT]) aggregateNextErrChannels() chan error {
	if len(s.NextErrChs) == 1 {
		// Optimized case for just one error channel.
		return s.NextErrChs[0]
	}

	// Create an error channel to aggregate all the next stages' error channels.
	nextStagesAggregatedErrCh := make(chan error)

	// The wait group serves to know when all next stages' error channels have been closed.
	wg := sync.WaitGroup{}
	wg.Add(len(s.NextErrChs))

	// Aggregate any possible error coming from any next stage into the aggregated channel.
	for i, nextErrCh := range s.NextErrChs {
		i := i
		nextErrCh := nextErrCh // Local copy for the capture of the goroutine next.
		go func() {
			defer wg.Done()
			for err := range nextErrCh {
				debugPrintf("[%s] got error from next stage at channel %d\n", s.Name, i)
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
	if len(s.IncomingChs) == 1 {
		// Optimized case for just one incoming channel.
		return s.IncomingChs[0]
	}

	return s.buildAggregatedInput()
}

func (s *Stage[IN, OUT]) readIncomingConcurrently() chan IN {
	debugPrintf("[%s] concurrent input, stage = %p\n", s.Name, s)
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
				debugPrintf("[%s] aggregating incoming data\n", s.Name)
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

func (s *Stage[IN, OUT]) readIncomingSequentially() chan IN {
	// Create a slice of input channels.
	inChannels := make([]chan IN, len(s.IncomingChs))
	copy(inChannels, s.IncomingChs)

	// Create aggregated channel.
	aggregated := make(chan IN)
	go func() {
		for i := 0; ; i = (i + 1) % len(inChannels) {
			in, ok := <-s.IncomingChs[i]
			if !ok {
				debugPrintf("[%s] aggregated input: channel %d closed\n", s.Name, i)
				// This incoming channel was closed.
				util.RemoveElemFromSlice(&inChannels, i)
				if len(inChannels) == 0 { // no more open channels, break out of loop.
					break
				}
				i--
			} else {
				aggregated <- in
				debugPrintf("[%s] aggregated input: data on channel %d\n", s.Name, i)
			}
		}
		// All channels have closed.
		close(aggregated)
	}()
	return aggregated
}

type None struct{}

type noError struct{}

func (noError) Error() string { return "" }

var NoMoreData = noError{}

// deleteme: remove all this debug infrastructure.
type debugLine struct {
	Time time.Time
	Line string
}

var debugLines []debugLine
var debugLinesMu sync.Mutex

func debugPrintf(format string, args ...any) {
	// fmt.Printf(format, args...)
	// debugPrintfReal(format, args...)
}

func debugPrintfReal(format string, args ...any) {
	t := time.Now()
	line := fmt.Sprintf(format, args...)
	debugLinesMu.Lock()
	defer debugLinesMu.Unlock()
	debugLines = append(debugLines, debugLine{
		Time: t,
		Line: line,
	})
}

func PrintAllDebugLines() {
	sort.Slice(debugLines, func(i, j int) bool {
		return debugLines[i].Time.Before(debugLines[j].Time)
	})
	for i, d := range debugLines {
		if i > 999 {
			// Max of 1000 lines of output.
			fmt.Printf("... more output (%d lines omitted) ...\n", len(debugLines)-1000)
			break
		}
		fmt.Printf("[%3d] [%30s] %s",
			i,
			d.Time.Format(time.StampNano),
			d.Line,
		)
	}
}
