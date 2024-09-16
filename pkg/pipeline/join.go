package pipeline

import (
	"fmt"
)

func JoinPipelines(pipelines ...*Pipeline) *Pipeline {
	// deleteme
	return nil
}

func JoinTwoPipelines[T any](p1, p2 *Pipeline) (*Pipeline, error) {
	// Find sink of p1.
	sink := p1.Sink.(*Sink[T])
	source := p2.Source.(*Source[T])
	if source.sourceIncomingCh == nil {
		return nil, fmt.Errorf("source of p2 is not using an incoming channel")
	}

	// The joining stage, acting as the "glue" between p1.sink and p2.source.
	joiningStage := newJointStage(sink, source, p2)

	// The pipeline stages contains all the stages from p1 except the sink, and a new joiningStage.
	stages := make([]StageLike, 0)
	for _, s := range p1.Stages {
		if _, ok := s.(SinkLike); !ok {
			stages = append(stages, s)
		}
	}
	stages = append(stages, joiningStage)

	// We need a new pipeline that connects the two.
	p, err := NewPipeline(
		func(p *Pipeline) {
			// Linking function.
			DebugPrintf("[joint pipeline] link function linking both pipelines\n")

			// The second pipeline, p2, is prepared and linked before each sink's onResume event.
			// This allows for an autoresume call working even at the cross-pipeline boundaries,
			// namely, having the p1.sink as its target.

			// Call the original p1 link function.
			p1.linkFunc(p1)

			joiningStage.p2 = p2
			joiningStage.joinStages()
		},
		WithStages(stages...),
	)
	if err != nil {
		return nil, err
	}

	return p, nil
}

// jointStage joins the sink of the first pipeline with the whole second pipeline, using
// the second pipeline as the joint point.
type jointStage[T any] struct {
	*StageBase
	sink   *Sink[T]
	source *Source[T]
	p2     *Pipeline
}

var _ StageLike = (*jointStage[int])(nil)
var _ SinkLike = (*jointStage[int])(nil)

func newJointStage[T any](
	sink *Sink[T],
	source *Source[T],
	secondPipeline *Pipeline,
) *jointStage[T] {
	return &jointStage[T]{
		StageBase: &StageBase{
			Name: fmt.Sprintf("%s_join_%s", sink.Name, source.Name),
		},
		sink:   sink,
		source: source,
		p2:     secondPipeline,
	}
}

func (j *jointStage[T]) Prepare() {
	// The second pipeline is prepared every time before calling sink.Resume()
	j.sink.Prepare()
}

func (j *jointStage[T]) PrepareSink() {
	// PrepareSink should never be called on the jointStage, unless requesting autoresume
	// on the jointStage itself, which is impossible.
	// However, to allow users to pick up the stages from a joint pipeline and use them in a
	// new, different pipeline, which configures autoresume on the sink of the joint pipeline,
	// we allow the call and forward it to the previous sink.
	j.sink.PrepareSink()
}

func (j *jointStage[T]) Resume() {
	// Calling the sink's Resume method will trigger the onResume event.
	// The source is resumed right at the sink's onResume event, before executing the resuming
	// of the sink.
	j.sink.Resume()
}

// joinStages must be called once, after the new pipeline's stages have been prepared,
// but before resuming them, usually at the new pipeline's link function.
func (j *jointStage[T]) joinStages() {
	// Sketch of the original scenario:
	// ----> B1 ----> sink ----> sink's_None_output
	// ----> B2 ---/
	//
	// After modification with jointStage:
	// ----> B1 ----> sink ----> p2.source
	// ----> B2 ---/

	// -- Do once, after prepare but before resume.
	// (1) Remember the original sink's process function.
	sinkOrigProcessFunc := j.sink.ProcessFunc

	// (2) Remember the original sink's OnNoMoreData function
	sinkOrigOnNoMoreData := j.sink.onNoMoreData

	// (3) Close the original source incoming channel.
	DebugPrintf("[%s] closing source channel %s\n", j.Name, chanPtr(j.source.sourceIncomingCh))
	close(j.source.sourceIncomingCh)

	// (4) Remember the source's original onResume function, before replacing it.
	origSourceOnResume := j.source.onResume

	// -- Do every time autoresume kicks in, until sink's ErrCh is closed.
	j.sink.onResume = func() {
		DebugPrintf("[%s] sink.onResume() called\n", j.Name)
		// (1) New source incoming channel.
		j.source.onResume = func() {
			// Call the original onResume for the source.
			origSourceOnResume()
			// If there was any onResume replacing it, ensure the source channel is the new one.
			j.source.sourceIncomingCh = make(chan T)
		}
		DebugPrintf("[%s] creating new source channel for [%s]: %s\n",
			j.Name, j.source.Name, chanPtr(j.source.sourceIncomingCh))

		// (2) Resume (which also prepares) the whole p2 pipeline.
		DebugPrintf("[%s] resuming second pipeline\n", j.Name)
		j.p2.Resume()

		// (3) Set the p2.source's TopErr channel as one of the p1.sink's next err channels.
		j.sink.NextErrChs = append(j.sink.NextErrChs, j.source.TopErrCh)
		DebugPrintf("[%s] added source's TopErr to sink's next error channels\n", j.Name)

		// (4) Every time the sink finishes processing a message, forward it to p2.source, unless
		// the sink specifies NoMoreData or error, where we close the p2.source incoming channel,
		// while at the same time the sink will close it's dummy output and next error channels.
		// Since the next error channel number 2 (sink.NextErrChs[1]) is the top level p2.source's
		// error channel, the sink will also receive errors from the second pipeline.
		j.sink.ProcessFunc = func(in T) ([]None, []int, error) {
			j.source.sourceIncomingCh <- in
			_, _, err := sinkOrigProcessFunc(in)
			DebugPrintf("[%s] msg: '%v' on original sink. Processing error: %v\n", j.Name, in, err)
			if err == NoMoreData {
				close(j.source.sourceIncomingCh)
			}
			return nil, nil, err
		}

		// (5) Capture the OnNoMoreData event, to also close the source's incoming channel.
		j.sink.onNoMoreData = func() ([]None, []int, error) {
			DebugPrintf("[%s] OnNoMoreData() called on sink. Closing source's incoming channel\n",
				j.Name)
			close(j.source.sourceIncomingCh)
			return sinkOrigOnNoMoreData()
		}
	}
}
