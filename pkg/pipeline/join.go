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

			// Now we need to link the source input channel of p2 to all the output channels
			// of p1's sink. And error channels conversely.
			debugPrintf("[joint pipeline] setting joint stage\n")
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

	dataCh chan T
}

var _ StageLike = (*jointStage[int])(nil)

func newJointStage[T any](sink *Sink[T], source *Source[T]) *jointStage[T] {
	return &jointStage[T]{
		StageBase: &StageBase{
			Name: fmt.Sprintf("%s_join_%s", sink.Name, source.Name),
		},
		sink:   sink,
		source: source,
		dataCh: make(chan T),
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

// joinStages must be called after all stages have been prepared, but before resuming them.
// A good place is the link function of the joint pipeline.
func (j *jointStage[T]) joinStages() {
	j.joinDataChannels()
	j.joinErrorChannels()
}

func (j *jointStage[T]) joinDataChannels() {
	// Unlink the source's channel and use this joint stage's data channel as source.
	debugPrintf("[%s] p2.source orig channel: %s, new: %s\n",
		j.Name, chanPtr(j.source.sourceIncomingCh), chanPtr(j.dataCh))
	j.source.sourceIncomingCh = j.dataCh

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
				debugPrintf("[%s] got '%v' on sink's %d: %s. Sending to %s & %s\n",
					j.Name, out, i, chanPtr(sinkInCh), chanPtr(newSinkInCh), chanPtr(j.dataCh))
				newSinkInCh <- out
				j.dataCh <- out
			}
			// When the original channel is closed, close the new one as well.
			debugPrintf("[%s] closing new incoming channel at %d: %s (old is %s)\n",
				j.Name, i, chanPtr(newSinkInCh), chanPtr(sinkInCh))
			close(newSinkInCh)
		}(sinkInCh, newSinkInCh)

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
			j.Name, chanPtr(j.dataCh))
		close(j.dataCh)
	}()
}

// joinErrorChannels prepares the error channels so that if the sink's process function OR
// the source error channel return an error, everything is stopped and the error returned to
// the previous stages.
func (j *jointStage[T]) joinErrorChannels() {
	// This is the original error channel, linked to previous stages.
	// Only emits processing errors, but it's the one linked to previous stages.
	origErrCh := j.sink.ErrCh

	// This is the new error channel that will receive errors from the sink's processing and
	// from other next stages, namely the source of the second pipeline.
	newErrCh := make(chan error)

	// Read errors from processing at the sink.
	go func(origErrCh chan error) {
		for err := range origErrCh {
			debugPrintf("[%s] received error: %v at channel %s, resent to %s\n",
				j.Name, err, chanPtr(origErrCh), chanPtr(newErrCh))
			if err != nil {
				// Sending an error to the sink's error channel forces the sink to make
				// a call to breakPipelineAndWait.
				newErrCh <- err

				// At sink.breakPipelineAndWait, we close the outgoing sink channel.
				// Also close the next pipeline source channel as well,
				// to signal that next stage to stop. We will need the source's error channel at
				// the sink's next stage error channel slice.
				debugPrintf("[%s] closing joint source [%s] input channel %s\n",
					j.Name, j.source.Name, chanPtr(j.source.sourceIncomingCh))
				close(j.source.sourceIncomingCh)

				// The sink's error channel will be closed by sink.breakPipelineAndWait when
				// all next stage error channels have returned.
				return
			}
		}
		// Closing the sink's original error channel means the sink has finished completely,
		// also reading the next stages error channels. Nothing to do then.

	}(origErrCh)

	// Replace original error channel with the new one. This pushes errors up the pipeline.
	debugPrintf("[%s] replacing original error channel %s with %s\n",
		j.Name, chanPtr(j.sink.ErrCh), chanPtr(newErrCh))
	j.sink.ErrCh = newErrCh

	// The sink will close its (single) next stage error channel once the out channel is closed.
	// The next stages aggregated error is created right at Resume(), which means that we can
	// create an extra next stage error with the new error channel and let the whole sink stage
	// work as usual. The next stages aggregated error will close when both are closed.
	j.sink.NextErrChs = append(j.sink.NextErrChs, j.source.TopErrCh)

	// Now read any possible error from the new error channel at the sink, and pass it to the
	// original error channel. Close the original when the new one is closed.
	// This re-enables signaling errors to previous stages.
	go func() {
		for err := range newErrCh {
			if err != nil {
				origErrCh <- err
			}
		}
		debugPrintf("[%s] closing original error channel %s\n", j.Name, chanPtr(origErrCh))
		close(origErrCh)
	}()
}
