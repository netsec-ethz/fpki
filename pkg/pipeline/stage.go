package pipeline

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	tr "github.com/netsec-ethz/fpki/pkg/tracing"
	"github.com/netsec-ethz/fpki/pkg/util"
)

const (
	WaitIsTooLong    = 1000 * time.Millisecond // If receiving/sending takes longer -> emit trace.
	ProcessIsTooLong = 1000 * time.Millisecond // If processing function takes longer -> emit trace.
)

type StageLike interface {
	Prepare(context.Context)
	Resume(context.Context)
	Base() *StageBase
}

type StageBase struct {
	Tracer                    tr.Tracer       // The tracer for this service.
	Ctx                       context.Context // Running context of this stage.
	Name                      string          // Name of the stage.
	ErrCh                     chan error      // To be read by the previous stage (or trigger, if this is Source).
	StopCh                    chan None       // Indicates to this stage to stop.
	NextErrChs                []chan error    // Next stage's error channel.
	NextStagesAggregatedErrCh chan error      // Aggregated nexErrChs
	onReceivedData            func()          // Callback after getting data from incoming.
	onResume                  func()          // Callback before Resume() starts.
	onProcessed               func()          // Callback after process.
	onSent                    func()          // Callback after sent to outgoing.
	onErrorSending            func(error, []int)
}

func newStageBase(name string) StageBase {
	return StageBase{
		Tracer:         tr.GetTracer(name),
		Name:           name,
		onReceivedData: func() {},             // Noop.
		onResume:       func() {},             // Noop.
		onProcessed:    func() {},             // Noop.
		onSent:         func() {},             // Noop.
		onErrorSending: func(error, []int) {}, // Noop.
	}
}

func (s *StageBase) Base() *StageBase {
	return s
}

type Stage[IN, OUT any] struct {
	StageBase                     // Non type dependent fields.
	IncomingChs        []chan IN  // Incoming data channel to process.
	OutgoingChs        []chan OUT // Data to the next stages goes here.
	AggregatedIncomeCh chan IN    // Aggregated input channel.

	cacheCompletedOutgoingIndices []int // Cache to reuse space.

	ProcessFunc func(in IN) ([]OUT, []int, error) // From 1 IN to n OUT, using n channels.
	streamFunc  func(*[]OUT, *[]int) error        // Streaming function.

	// Before stopping the pipeline. This function allows processing before stopping the pipeline.
	onNoMoreData func() ([]OUT, []int, error)

	buildAggregatedInput func() chan IN // Alter by With* modifier.
	sendOutputs          func(          // Selectable by With* modifier.
		[]OUT,
		[]int,
		*bool,
		*bool,
		*error,
	) []int
}

var _ StageLike = (*Stage[int, string])(nil)

func NewStage[IN, OUT any](
	name string,
	options ...option[IN, OUT],
) *Stage[IN, OUT] {

	s := &Stage[IN, OUT]{
		StageBase:                     newStageBase(name),
		IncomingChs:                   make([]chan IN, 1),  // Per default, just one channel.
		OutgoingChs:                   make([]chan OUT, 1), // Per default, just one channel.
		cacheCompletedOutgoingIndices: make([]int, 0, 16),  // Init to 16 outputs per process call.
		streamFunc: func(o *[]OUT, i *[]int) error {
			return NoMoreData
		},
		onNoMoreData: func() ([]OUT, []int, error) { // Noop.
			return nil, nil, nil
		},
	}
	s.buildAggregatedInput = s.readIncomingConcurrently

	s.sendOutputs = s.sendOutputsConcurrent

	for _, opt := range options {
		opt.stage(s)
	}

	return s
}

// LinkStagesAt links an outgoing channel of a stage to an incoming one of another.
func LinkStagesAt[IN, OUT, LAST any](
	prev *Stage[IN, OUT],
	outIndex int,
	next *Stage[OUT, LAST],
	inIndex int,
) {
	DebugPrintf("linking  data channels [%s] -> [%s]:%s\n",
		prev.Name, next.Name, chanPtr(next.IncomingChs[inIndex]),
	)
	prev.OutgoingChs[outIndex] = next.IncomingChs[inIndex]

	DebugPrintf("linking error channels [%s] <- [%s]:%s\n",
		prev.Name, next.Name, chanPtr(next.ErrCh),
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

// LinkStagesDistribute connects the single output channel of the prev stage to the single input
// channel of multiple next stages.
// This is done by creating a channel here, that will be closed by the prev stage when it's done.
// The created channel will be used as output of the prev stage, and input of all next stages.
// The error channels remain connected the same way as with LinkStagesFanOut.
func LinkStagesDistribute[IN, OUT, NEXT any](
	prev *Stage[IN, OUT],
	nextStages ...*Stage[OUT, NEXT],
) {
	if len(prev.OutgoingChs) != 1 {
		panic("use the distribute-connector with a single-output previous stage")
	}
	for i, next := range nextStages {
		if len(next.IncomingChs) != 1 {
			panic(fmt.Errorf("use the distribute-connector with a single-input next stage. "+
				"Stage indexed in this call as %d has %d input channels", i, len(next.IncomingChs)))
		}
	}

	ch := make(chan OUT)
	prev.OutgoingChs[0] = ch

	// All next stages have the new channel as their input.
	for _, next := range nextStages {
		DebugPrintf("linking data channels [%s] -> [%s]:%s\n", prev.Name, next.Name, chanPtr(ch))
		next.IncomingChs[0] = ch
	}

	// All next stages send the error report to the previous stage single next-stage-error channel.
	// Spawn a goroutine per next stage to read errors and pass them to the prev stage.
	errCh := make(chan error)
	prev.NextErrChs[0] = errCh
	DebugPrintf("linking error channels to [%s]:%s <-\n", prev.Name, chanPtr(errCh))

	wg := sync.WaitGroup{}
	wg.Add(len(nextStages))
	for _, next := range nextStages {
		next := next
		go func() {
			defer wg.Done() // Done when the error channel of next stage i is closed.
			for err := range next.ErrCh {
				errCh <- err
			}
		}()
		DebugPrintf("\tlinking error channels [%s] <- [%s]:%s\n",
			prev.Name, next.Name, chanPtr(next.ErrCh))
	}
	go func() {
		// Wait for all the next stages to close their error channel.
		wg.Wait()
		// Then close the aggregated one.
		close(errCh)
	}()
}

// Prepare creates the necessary fields of the stage to be linked with others.
// It MUST NOT spawn any goroutines at this point.
func (s *Stage[IN, OUT]) Prepare(ctx context.Context) {
	s.Ctx = ctx
	s.ErrCh = make(chan error)
	s.StopCh = make(chan None)

	// Clear the aggregated input channel if set.
	s.AggregatedIncomeCh = nil
	for i := range s.IncomingChs {
		s.IncomingChs[i] = make(chan IN)
	}

	s.NextErrChs = make([]chan error, len(s.OutgoingChs))

	// Cannot aggregate the incoming channels here, as there is logic to join two pipelines,
	// that relies on the aggregated input to not start reading input from the incoming channels
	// until Resume is called.

	// Cannot aggregate the error channels here, as they will be modified after linking with
	// other stages.
}

// Resume resumes processing from this stage.
// This function creates new channels for the incoming data, error and stop channels.
func (s *Stage[IN, OUT]) Resume(ctx context.Context) {
	s.Ctx = ctx

	// Just before resuming, call the internal event function.
	s.onResume()

	// The aggregated channel will receive all incoming data.
	s.AggregatedIncomeCh = s.aggregateIncomingChannels()

	// The aggregated channel will receive error messages from the N next stage error channels.
	// All the nextStageErrCh are created and linked from other stages at this point.
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
	DebugPrintf("[%s] exiting _____________________________ initial err=%v\n", s.Name, initialErr)

	// Indicate next stage to stop.
	for i, outCh := range s.OutgoingChs {
		DebugPrintf("[%s] closing output channel %d/%d: %s\n",
			s.Name, i, len(s.OutgoingChs), chanPtr(outCh))
		close(outCh)
	}

	// Read its status:
	DebugPrintf("[%s] waiting for next stage's error\n", s.Name)
	err := <-s.NextStagesAggregatedErrCh
	DebugPrintf("[%s] read next stage's error: %v\n", s.Name, err)

	// Coalesce with any error at this stage.
	initialErr = util.ErrorsCoalesce(initialErr, err)

	// Propagate error backwards.
	DebugPrintf("[%s] closing error channel %s, previous stage will be notified\n",
		s.Name, chanPtr(s.ErrCh))
	if initialErr != nil {
		// Propagate error backwards.
		s.ErrCh <- initialErr
	}

	// Close our own error channel.
	DebugPrintf("[%s] closed main error channel %s\n", s.Name, chanPtr(s.ErrCh))
	close(s.ErrCh)

	// Close the stop channel indicator.
	DebugPrintf("[%s] closing stop channel %s\n", s.Name, chanPtr(s.StopCh))
	close(s.StopCh)

	DebugPrintf("[%s] all done, stage is stopped\n", s.Name)
	return initialErr
}

func (s *Stage[IN, OUT]) processThisStage() {
	var foundError error
	var shouldReturn bool
	var shouldBreakReadingIncoming bool
	var sendingError bool

	// deleteme decide if we want a service per "operation" (processing, sending, etc), or per
	// stage instance (domain_batcher_01, etc), or a mix.
	// traIncoming := tr.T("incoming")
	// traProcessing := tr.T("processing")
	// traSending := tr.T("sending")
	traIncoming := s.Tracer
	traProcessing := s.Tracer
	traSending := s.Tracer
	lastTiming := tr.Now()

	var outs []OUT
	var outChIndxs []int
	var err error
readIncoming:
	for {
		DebugPrintf("[%s] select-blocked on input: %s\n", s.Name, chanPtr(s.AggregatedIncomeCh))
		_, spanIncoming := traIncoming.Start(s.Ctx, "incoming")
		tr.SetAttrString(spanIncoming, "name", s.Name)

		select {
		case <-s.StopCh:
			// We have been instructed to stop, without reading any other channel.
			DebugPrintf("[%s] stop requested\n", s.Name)
			return

		case err := <-s.NextStagesAggregatedErrCh:
			DebugPrintf("[%s] got ERROR while reading incoming from next stage\n", s.Name)
			foundError = err
			break readIncoming

		case in, ok := <-s.AggregatedIncomeCh:
			if DebugEnabled {
				// Need this if-guard to prevent the arguments from being evaluated by the compiler,
				// because if it does, it will allocate memory for "in" when e.g. IN = Certificate.
				var v any = in
				if s, ok := any(in).(fmt.Stringer); ok {
					v = s.String()
				}
				DebugPrintf("[%s] incoming? %v, value: %v\n", s.Name, ok, v)
			}
			s.onReceivedData()

			tr.SpanIfLongTime(WaitIsTooLong, &lastTiming, spanIncoming)
			_, spanProcessing := traProcessing.Start(s.Ctx, "processing")
			tr.SetAttrString(spanProcessing, "name", s.Name)

			if !ok {
				// Incoming channel was closed. No data to be written to outgoing channel.
				DebugPrintf("[%s] input indicates no more data\n", s.Name)
				outs, outChIndxs, err = s.onNoMoreData()
				shouldBreakReadingIncoming = true // Regardless of err, request to break.
			} else {
				outs, outChIndxs, err = s.ProcessFunc(in)
			}
			s.onProcessed()

			tr.SpanIfLongTime(ProcessIsTooLong, &lastTiming, spanProcessing)
			_, spanSending := traSending.Start(s.Ctx, "sending ")
			tr.SetAttrString(spanSending, "name", s.Name)

			switch err {
			case nil: // do nothing
			case StreamOutput: // do nothing. There is more data to send.
			case NoMoreData:
				// No more data, no error.
				// Break out of the reading loop, after processing (possibly empty) output.
				shouldBreakReadingIncoming = true
			default:
				// Processing failed, break immediately.
				foundError = err
				break readIncoming
			}

			// Inner loop sending several outputs, indicated by StreamOutput.
			for {
				// We have multiple outputs to multiple channels.
				DebugPrintf("[%s] sending %d outputs to channels %v\n", s.Name, len(outs), outChIndxs)
				failedIndices := s.sendOutputs(
					outs,
					outChIndxs,
					&shouldReturn,
					&sendingError,
					&foundError,
				)
				s.onSent()
				if tr.Enabled {
					defer tr.SpanIfLongTime(WaitIsTooLong, &lastTiming, spanSending)
				}

				DebugPrintf("[%s] sendingError = %v, shouldReturn = %v, shouldBreak = %v\n",
					s.Name, sendingError, shouldReturn, shouldBreakReadingIncoming)
				if sendingError {
					s.onErrorSending(foundError, failedIndices)
				}

				// Determine the next action to do.
				if shouldReturn {
					return
				}
				if shouldBreakReadingIncoming || sendingError {
					break readIncoming
				}

				// If the stage is streaming output, keep on sending.
				if err != StreamOutput {
					break
				}
				err = s.streamFunc(&outs, &outChIndxs)
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
) []int {
	failedIndices := []int{}
	for i := range outs {
		out := outs[i]
		outChIndex := outChIndxs[i]

		// We attempt to write the out data to the outgoing channel.
		// Because this can block, we must also listen to any error coming from the
		// next stage, plus our own stop signal.
		DebugPrintf("[%s] attempting to send %v to channel %d: %s\n",
			s.Name, out, outChIndex, chanPtr(s.OutgoingChs[outChIndex]))
		select {
		case s.OutgoingChs[outChIndex] <- out:
			// Success writing to the outgoing channel, nothing else to do.
			DebugPrintf("[%s] value %v sent to channel %d: %s\n",
				s.Name, out, outChIndex, chanPtr(s.OutgoingChs[outChIndex]))
		case err := <-s.NextStagesAggregatedErrCh:
			DebugPrintf("[%s] ERROR while sending at channel %d the value %v, error: %v\n",
				s.Name, outChIndex, out, err)
			// We received an error from next stage while trying to write to it.
			*foundError = err
			*shouldBreakReadingIncoming = true
			failedIndices = append(failedIndices, i)
		case <-s.StopCh:
			// We have been instructed to stop, without reading any other channel.
			DebugPrintf("[%s] instructed to stop\n", s.Name)
			*shouldReturn = true
		}
	}

	return failedIndices
}

// sendOutputsConcurrent sends the possibly multiple outputs to each out channel concurrently.
// This function will allocate memory, since it spawns a goroutine per output channel, and
// synchronizes with all of them.
// TODO: create the goroutines at NewStage time, and unblock them with e.g. a sync.Cond.
func (s *Stage[IN, OUT]) sendOutputsConcurrent(
	outs []OUT,
	outChIndxs []int,
	shouldReturn *bool,
	shouldBreakReadingIncoming *bool,
	foundError *error,
) []int {
	failedIndices := []int{}
	// For each output spawn a go routine sending it to the appropriate channel.
	wg := sync.WaitGroup{}
	wg.Add(len(outs))

	muShouldReturn := sync.Mutex{}
	muShouldBreakReadingIncoming := sync.Mutex{} // Also for foundError and indices.

	for i := range outs {
		i := i
		go func() {
			out := outs[i]
			outChIndex := outChIndxs[i]

			defer wg.Done()
			// We attempt to write the out data to the outgoing channel.
			// Because this can block, we must also listen to any error coming from the
			// next stage, plus our own stop signal.
			DebugPrintf("[%s] attempting to send %v to channel %d: %s\n",
				s.Name, out, outChIndex, chanPtr(s.OutgoingChs[outChIndex]))
			select {
			case s.OutgoingChs[outChIndex] <- out:
				// Success writing to the outgoing channel, nothing else to do.
				DebugPrintf("[%s] value %v sent to channel %d: %s\n",
					s.Name, out, outChIndex, chanPtr(s.OutgoingChs[outChIndex]))
			case err := <-s.NextStagesAggregatedErrCh:
				DebugPrintf("[%s] ERROR while sending at channel %d the value %v: %v\n",
					s.Name, outChIndex, out, err)
				// We received an error from next stage while trying to write to it.
				muShouldBreakReadingIncoming.Lock()
				*foundError = err
				*shouldBreakReadingIncoming = true
				failedIndices = append(failedIndices, i)
				muShouldBreakReadingIncoming.Unlock()
			case <-s.StopCh:
				// We have been instructed to stop, without reading any other channel.
				DebugPrintf("[%s] instructed to stop\n", s.Name)
				muShouldReturn.Lock()
				*shouldReturn = true
				muShouldReturn.Unlock()
			}
		}()
	}
	// Wait for all outputs to be sent.
	wg.Wait()

	return failedIndices
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
) []int {
	failedIndices := []int{}
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
			if DebugEnabled {
				DebugPrintf("[%s] attempting to send %v to channel %d: %s\n",
					s.Name, out, outChIndex, chanPtr(s.OutgoingChs[outChIndex]))
			}
			select {
			case s.OutgoingChs[outChIndex] <- out:
				// Success writing to the outgoing channel, nothing else to do.
				s.cacheCompletedOutgoingIndices = append(s.cacheCompletedOutgoingIndices, i)
				if DebugEnabled {
					DebugPrintf("[%s] value %v sent to channel %d: %s\n",
						s.Name, out, outChIndex, chanPtr(s.OutgoingChs[outChIndex]))
				}
			case err := <-s.NextStagesAggregatedErrCh:
				if DebugEnabled {
					DebugPrintf("[%s] ERROR while sending at channel %d the value %v: %v\n",
						s.Name, outChIndex, out, err)
				}
				// We received an error from next stage while trying to write to it.
				*foundError = err
				shouldStopSending = true
				failedIndices = append(failedIndices, i)
				break eachOutput
			case <-s.StopCh:
				// We have been instructed to stop, without reading any other channel.
				DebugPrintf("[%s] instructed to stop\n", s.Name)
				*shouldReturn = true
			default: // the outCh is not ready, try with next value/channel
				if DebugEnabled {
					DebugPrintf("[%s] out channel %d not ready\n", s.Name, outChIndex)
				}
			}
		}
		util.RemoveElementsFromSlice(&outs, s.cacheCompletedOutgoingIndices)
		util.RemoveElementsFromSlice(&outChIndxs, s.cacheCompletedOutgoingIndices)
		if len(outs) == 0 || *shouldReturn || shouldStopSending {
			DebugPrintf("[%s] break sending: len(outs) = %d, shouldReturn = %v, shouldBreak = %v\n",
				s.Name, len(outs), *shouldReturn, *shouldBreakReadingIncoming)
			break
		}
		runtime.Gosched() // Yield processor before we attempt to send again.
	}

	// Aggregate the stop-sending-flag to also stop reading.
	*shouldBreakReadingIncoming = *shouldBreakReadingIncoming || shouldStopSending

	return failedIndices
}

func (s *Stage[IN, OUT]) aggregateNextErrChannels() chan error {
	if len(s.NextErrChs) == 1 {
		DebugPrintf("[%s] aggregated next error channel is first next error channel: %s\n",
			s.Name, chanPtr(s.NextErrChs[0]))
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
		i, nextErrCh := i, nextErrCh
		DebugPrintf("[%s] aggregated next error channel %s uses channel %d: %s\n",
			s.Name, chanPtr(nextStagesAggregatedErrCh), i, chanPtr(nextErrCh))

		go func() {
			defer wg.Done()
			for err := range nextErrCh {
				DebugPrintf("[%s] got error %v from next stage at channel %d: %s\n",
					s.Name, err, i, chanPtr(nextErrCh))
				nextStagesAggregatedErrCh <- err
			}
			// When the nextErrCh of next stage i is closed, this goroutine signals the wg.
			DebugPrintf("[%s] aggregated next error channel %s sees channel [%d]: %s is closed\n",
				s.Name, chanPtr(nextStagesAggregatedErrCh), i, chanPtr(nextErrCh))
		}()
	}

	// Spin a goroutine to close the aggregated channel when all the next stages' ones are closed.
	go func() {
		// Wait until all nextErrCh have been closed.
		wg.Wait()
		// Now close the aggregated channel.
		DebugPrintf("[%s] closing aggregated error channel %s\n",
			s.Name, chanPtr(nextStagesAggregatedErrCh))
		close(nextStagesAggregatedErrCh)
	}()
	return nextStagesAggregatedErrCh
}

func (s *Stage[IN, OUT]) aggregateIncomingChannels() chan IN {
	if s.AggregatedIncomeCh != nil {
		// We have already goroutines reading from the incoming channels.
		DebugPrintf("[%s] aggregated input channel existed %s. Reusing\n",
			s.Name, chanPtr(s.AggregatedIncomeCh))
		return s.AggregatedIncomeCh
	}
	if len(s.IncomingChs) == 1 {
		// Optimized case for just one incoming channel.
		DebugPrintf("[%s] aggregated input is first channel: %s\n",
			s.Name, chanPtr(s.IncomingChs[0]))
		return s.IncomingChs[0]
	}

	aggregatedInput := s.buildAggregatedInput()
	inputs := make([]string, len(s.IncomingChs))
	for i, ch := range s.IncomingChs {
		inputs[i] = chanPtr(ch)
	}
	DebugPrintf("[%s] built aggregated input %s from (%s)\n",
		s.Name, chanPtr(aggregatedInput), strings.Join(inputs, ", "))
	return aggregatedInput
}

func (s *Stage[IN, OUT]) readIncomingConcurrently() chan IN {
	// Create a new channel to aggregate all the incoming data from different channels.
	aggregated := make(chan IN)

	// The wait group serves to know when all incoming channels have been closed.
	wg := sync.WaitGroup{}
	wg.Add(len(s.IncomingChs))

	// Aggregate any possible incoming data into the aggregated channel.
	for i, incomingCh := range s.IncomingChs {
		i, incomingCh := i, incomingCh // Local copy for the capture of the goroutine next.
		go func() {
			defer wg.Done()
			for in := range incomingCh {
				// DebugPrintf("[%s] aggregated input %v at channel %d: %s\n",
				// 	s.Name, in, i, chanPtr(incomingCh))
				aggregated <- in
			}
			// When the incomingCh number i is closed, signal the wait group.
			DebugPrintf("[%s] aggregated input: channel index %d: %s closed\n",
				s.Name, i, chanPtr(incomingCh))
		}()
	}

	// Spin a goroutine to close the aggregated channel when all the incoming ones are closed.
	go func() {
		// Wait until all incomingCh have been closed.
		wg.Wait()
		// Now close the aggregated channel.
		DebugPrintf("[%s] closing aggregated input %s\n", s.Name, chanPtr(aggregated))
		close(aggregated)
	}()
	return aggregated
}

func (s *Stage[IN, OUT]) readIncomingSequentially() chan IN {
	// Create a slice of input channels.
	inChannels := make([]chan IN, len(s.IncomingChs))
	copy(inChannels, s.IncomingChs)

	// For debug purposes, keep the original index of each channel (to print it out).
	originalIndicesDebugging := make(map[chan IN]int)
	for i, ch := range s.IncomingChs {
		originalIndicesDebugging[ch] = i
	}

	// Create aggregated channel.
	aggregated := make(chan IN)
	go func() {
		for i := 0; ; i = (i + 1) % len(inChannels) {
			debugIndex := originalIndicesDebugging[inChannels[i]]
			DebugPrintf("[%s] aggregated input: blocked at reading inCh[%d]: %s\n",
				s.Name, debugIndex, chanPtr(inChannels[i]))
			in, ok := <-inChannels[i]
			if !ok {
				DebugPrintf("[%s] aggregated input: channel index %d: %s closed\n",
					s.Name, debugIndex, chanPtr(inChannels[i]))
				// This incoming channel was closed.
				util.RemoveElemFromSlice(&inChannels, i)
				if len(inChannels) == 0 { // no more open channels, break out of loop.
					break
				}
				i--
			} else {
				aggregated <- in
				DebugPrintf("[%s] aggregated msg '%v' at channel %d: %s, forwarded to %s\n",
					s.Name, in, debugIndex, chanPtr(inChannels[i]), chanPtr(aggregated))
			}
		}
		// All channels have closed.
		DebugPrintf("[%s] closing aggregated input %s\n", s.Name, chanPtr(aggregated))
		close(aggregated)
	}()
	return aggregated
}

type None struct{}

var NoMoreData = noMoreData{}
var StreamOutput = streamOutput{}

type noMoreData struct{}
type streamOutput struct{}

func (noMoreData) Error() string   { return "NoMoreData" }
func (streamOutput) Error() string { return "StreamOutput" }
