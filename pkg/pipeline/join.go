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
// deleteme check that it is enough to just append the source's error to the sink's next errs.
func (j *jointStage[T]) joinErrorChannels() {
	j.sink.NextErrChs = append(j.sink.NextErrChs, j.source.TopErrCh)
}
