package pipeline

import (
	"fmt"
	"sync"
)

func JoinPipelines(pipelines ...*Pipeline) *Pipeline {
	// deleteme
	return nil
}

func JoinTwoPipelines[T any](p1, p2 *Pipeline) (*Pipeline, error) {
	// TODO: use pipeline.Source and .Sink to get the source and sink.

	// Find sink of p1.
	sink := p1.Sink.(*Sink[T])
	source := p2.Source.(*Source[T])
	if source.sourceIncomingCh == nil {
		return nil, fmt.Errorf("source of p2 is not using an incoming channel")
	}

	// The joining stage, acting as the "glue" between p1.sink and p2.source.
	joiningStage := newJointStage(sink, source)

	// The pipeline stages contains all the stages from p1 except the sink, a new joint stage, and
	// all the stages from p2 except the source.
	stages := make([]StageLike, 0)
	for _, s := range p1.Stages {
		if _, ok := s.(SinkLike); !ok {
			stages = append(stages, s)
		}
	}
	stages = append(stages, joiningStage)
	for _, s := range p2.Stages {
		if _, ok := s.(SourceLike); !ok {
			stages = append(stages, s)
		}
	}

	// We need a new pipeline that connects the two.
	p, err := NewPipeline(
		func(p *Pipeline) {
			// Linking function.
			debugPrintf("[joint pipeline] link function linking both pipelines\n")

			// Get the two pipelines ready.
			// Each pipeline's stages are contained inside the joint pipeline, with the exception
			// of p1.sink and p2.source, which are stored inside the joiningStage.
			// Those two stages need a call to Prepare as well.
			joiningStage.sink.Prepare()
			joiningStage.source.Prepare()

			// Call the original link functions.
			p1.linkFunc(p1)
			p2.linkFunc(p2)

			joiningStage.joinStages()
		},
		WithStages(stages...),
	)
	if err != nil {
		return nil, err
	}

	return p, nil
}

type jointStage[T any] struct {
	*StageBase
	sink   *Sink[T]
	source *Source[T]

	aggregatedInputCh chan T
}

var _ StageLike = (*jointStage[int])(nil)

func newJointStage[T any](sink *Sink[T], source *Source[T]) *jointStage[T] {
	return &jointStage[T]{
		StageBase: &StageBase{
			Name: fmt.Sprintf("%s_join_%s", sink.Name, source.Name),
		},
		sink:              sink,
		source:            source,
		aggregatedInputCh: make(chan T),
	}
}

func (j *jointStage[T]) Prepare() {} // Noop. Sink and source are prepared in link function.

func (j *jointStage[T]) Resume() {
	// This stage's channels are linked to the sink (previous stage) and source (next stage).
	// The go routines reading messages and forwarding them are already running.
	// Resume the sink and the source, in reverse order.
	j.source.Resume()
	j.sink.Resume()
}

// joinStages must be called once, after all stages have been prepared, but before resuming them.
// A right place is the link function of the joint pipeline.
func (j *jointStage[T]) joinStages() {
	j.joinDataChannels()
	j.joinErrorChannels()
}

func (j *jointStage[T]) joinDataChannels() {
	// Sketch of the original scenario:
	// ----> B1 ----> sink ----> sink's_None_output
	// ----> B2 ---/
	//
	// After modification with jointStage:
	// ----> B1 ----> joint_stage ----> sink ----> sink's_None_output
	// ----> B2 ---/      \------------------------------/
	//                                    |
	//                                     \------------------> p2.source

	// -- Do once, after prepare but before resume.
	// Replace the sink's sorted aggregated incoming channel: we read the messages in the same
	// order that the sink has specified.
	origAggregatedInput := j.sink.aggregateIncomingChannels()
	j.sink.AggregatedIncomeCh = make(chan T)

	// -- Do every time autoresume kicks in, until sink's ErrCh is closed.
	j.sink.onResume = func() {
		// Capture the sink's output None, as a ticker, to signal when to send to the source.
		close(j.sink.OutgoingChs[0]) // Stop the sink's dummy outgoing reader; sink closes nextErr.
		j.sink.OutgoingChs[0] = make(chan None)
		j.sink.NextErrChs[0] = make(chan error)

		// For every message received on the original sink input:
		// - Send it to the sink
		// - Block on the processDoneAtSink channel
		// - Once unblocked, send the same message to the source

		go func() {
			for in := range origAggregatedInput {
				j.sink.AggregatedIncomeCh <- in
				_, ok := <-j.sink.OutgoingChs[0] // Wait until the sink processes the message.
				if !ok {
					// Sink stopping or autoresuming.
					close(j.sink.NextErrChs[0])
					close(j.source.sourceIncomingCh)
					return
				}
				j.source.sourceIncomingCh <- in // Forward message to source.
			}
			// The original sink aggregated input is closed. Time to stop the sink.
			close(j.sink.AggregatedIncomeCh)
			close(j.source.sourceIncomingCh)
			// Wait until the sink processes the message.
			for range j.sink.OutgoingChs[0] {
			} // The sink has closed its dummy output: close the dummy nextErr.
			close(j.sink.NextErrChs[0])
		}()
	}
}

// joinDataChannels reads all the sink's original incoming channels (that are linked to the
// previous stages) and for each original channel, creates a new sink incoming channel in the
// same position. Each message coming from the original channel is:
//  1. Sent to the new sink incoming channel.
//  2. After processed at the sink, and if the sink's output channel is not closed, forward
//     this message to the joint channel. It will be picked up by p2.source.
func (j *jointStage[T]) joinDataChannelsOLD() {
	//
	// deleteme note that we need to listen to the p1.sink.OutgoingChs[0] for every None sent there,
	// signaling that the input was processed by the sink. When closing this outgoing channel,
	// the joint channel has to close p2.source.sourceIncomingCh as well.

	// For all incoming channels to the sink, read their messages and forward the messages to
	// the joint stage's data channel.
	wg := sync.WaitGroup{}
	wg.Add(len(j.sink.IncomingChs))
	for i, sinkInCh := range j.sink.IncomingChs {
		i, sinkInCh := i, sinkInCh
		// outCh is the original channel, linked with the previous stage.
		newSinkInCh := make(chan T)
		debugPrintf("[%s] sink's orig incoming %d: %s, new: %s\n",
			j.Name, i, chanPtr(sinkInCh), chanPtr(newSinkInCh))

		go func(sinkInCh chan T, newSinkInCh chan T) {
			defer wg.Done() // Signal the joint channel to close when all are closed.
			for out := range sinkInCh {
				debugPrintf("[%s] got '%v' on sink's original %d: %s. Sending to sink's new %s\n",
					j.Name, out, i, chanPtr(sinkInCh), chanPtr(newSinkInCh))
				// First send to sink itself. If accepted, it means it will process it.
				newSinkInCh <- out

				// When the sink has unblocked that incoming channel, forward the same value
				// (clone it) to the aggregated input channel. There is another goroutine that
				// forwards those values to the source.
				debugPrintf("[%s] value '%v' to aggregated joint input %s\n",
					j.Name, out, chanPtr(newSinkInCh))
				j.aggregatedInputCh <- out
			}
			// When the original channel is closed, close the new one as well.
			debugPrintf("[%s] closing new incoming channel at %d: %s (old is %s)\n",
				j.Name, i, chanPtr(newSinkInCh), chanPtr(sinkInCh))
			close(newSinkInCh)
		}(sinkInCh, newSinkInCh) // deleteme remove parameters (unnecessary)

		// Replace the original channel with the new one.
		j.sink.IncomingChs[i] = newSinkInCh
		debugPrintf("[%s] sink's %d incoming channel is now: %s\n",
			j.Name, i, chanPtr(j.sink.IncomingChs[i]))
	}
	// Aggregate the incoming channels again, after changing them.
	debugPrintf("[%s] re-aggregating input for sink [%s]. Old was: %s\n",
		j.Name, j.sink.Name, chanPtr(j.sink.AggregatedIncomeCh))
	j.sink.AggregatedIncomeCh = j.sink.aggregateIncomingChannels()

	// When all the original channels are closed, close our joint channel.
	go func() {
		wg.Wait()
		debugPrintf("[%s] all original data channels closed, closing joint: %s\n",
			j.Name, chanPtr(j.aggregatedInputCh))
		close(j.aggregatedInputCh)
		j.aggregatedInputCh = nil
	}()

	// Lastly, to support the sink stopping the pipeline at will (error or autoresume),
	// we insert a new output channel that when closed, will trigger the closing the input of
	// the source, hence stopping the pipeline from the sink forwards.
	extraOutputCh := make(chan None)
	// The sink creates a new OutgoingChs every time at PrepareSink, which is called from
	// the autoresume code if the sink is to autoresume.
	j.sink.OutgoingChs = append(j.sink.OutgoingChs, extraOutputCh)

	// close(j.source.sourceIncomingCh) // deleteme
	// Replace (or create) the source's incoming channel with a new one.
	j.source.sourceIncomingCh = make(chan T)

	// // Unlink the source's channel and use this joint stage's data channel as source.
	// debugPrintf("[%s] p2.source orig channel: %s, new: %s\n",
	// 	j.Name, chanPtr(j.source.sourceIncomingCh), chanPtr(j.aggregatedInputCh))
	// j.source.sourceIncomingCh = j.aggregatedInputCh

	go func() {
		// Forever read messages intended for the source, until:
		// - The sink requests to close: it will close its extra output channel.
		// - There is no more data for the source: we close the extra output
		// Do this forever, until the sink has no more data, i.e. j.dataCh is closed.

		for {
			// readIncomingOrClosingExtraOutput:
			select {
			// case in, ok := <-j.aggregatedInputCh:
			// 	debugPrintf("[%s] value %v (ok? %v) forwarded to source %s\n",
			// 		j.Name, in, ok, chanPtr(j.source.sourceIncomingCh))
			// 	if !ok {
			// 		// The sink doesn't have any more data, stop all.
			// 		// The sink will close its out channel index 0, we need to close the extra
			// 		// output channel.
			// 		close(extraOutputCh)

			// 		// We do not set extraOutputCh to nil to let this select pick the second
			// 		// case, where it is closed. We set j.aggregatedInputCh to nil to avoid
			// 		// this select case to be triggered again.
			// 		j.aggregatedInputCh = nil
			// 		break
			// 		// return
			// 		// break readIncomingOrClosingExtraOutput
			// 	}
			// 	j.source.sourceIncomingCh <- in
			case in := <-j.aggregatedInputCh:
				debugPrintf("[%s] value %v forwarded to source incoming channel %s\n",
					j.Name, in, chanPtr(j.source.sourceIncomingCh))
				j.source.sourceIncomingCh <- in
			case _, ok := <-extraOutputCh:
				if ok {
					// This is anomalous. We should never receive any value in this
					// output channel, as no processing function in the sink does even
					// know that it exists.
					// Report by crashing.
					panic(fmt.Errorf("logic error: received 'None' at extra output channel"+
						" in sink. Received at channel %s, by stage %s",
						chanPtr(extraOutputCh), j.Name))
				}
				// This channel is closed only from breakPipelineAndWait when closing outputs,
				// or the above select-case.
				// Close the source channel. This triggers the joint source to stop and send
				// the error back via its ErrCh.
				debugPrintf("[%s] sink requested to stop, closing source %s\n",
					j.Name, chanPtr(j.source.sourceIncomingCh))
				close(j.source.sourceIncomingCh)

				// Here, the source, when returning its state via sink.NextErrChs[1], will trigger
				// the sink to initiate one of:
				// - a return to previous stages: nothing to do here.
				// - autoresume: the onResume will trigger execution again. Nothing to do here.

				// extraOutputCh = nil // Avoid selecting this case again.

				// // // Before resuming the sink,
				// // // Create the source input channel again, as it won't be prepared.
				// // j.source.sourceIncomingCh = make(chan T)

				// // deleteme:
				// // if the sink is on autoresume, we need to know if it quits or autoresumes.
				// // - The way to know that the sink has resumed again is by capturing the call to Resume.
				// // - The way to know that the sink has quit is to capture its error channel:
				// // 	when it quits the error channel will be closed.
				// // If autoresuming, we have to wait until sink.Resume() is called, and after calling it,
				// // 	go again and link j.aggregatedInputCh to the source input channel: i.e. iterate again.

				// break readIncomingOrClosingExtraOutput
				return
			}
		}
	}()
}

// joinErrorChannels prepares the error channels so that if the sink's process function OR
// the source error channel return an error, everything is stopped and the error returned to
// the previous stages.
// deleteme check that it is enough to just append the source's error to the sink's next errs.
func (j *jointStage[T]) joinErrorChannels() {
	j.sink.NextErrChs = append(j.sink.NextErrChs, j.source.TopErrCh)
}
