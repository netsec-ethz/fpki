package pipeline

import (
	"context"
	"fmt"

	"github.com/netsec-ethz/fpki/pkg/util"
)

// Pipeline represents a data processing pipeline.
//
// Pipelines work in a forward-backward way:
// 1. Forward: the data is processed at each stage and sent forward to the next stage.
// 2. Backward: errors processing are sent back to the previous stage.
//
// For that, the creation of a pipeline involves:
//
// 1. Each stage is created.
// 1.1. Each stage has an error channel, meant to be read by the previous stage.
//
// 2. In reverse order, the stages are resumed.
// 2.1. Resuming a stage means creating the incoming channel and start processing the data.
// 2.2. The incoming channel of the next channel is the outgoing channel of this stage.
// 2.3. The error channel of the next stage is read until an error is encountered.
//
// 3. If the incoming channel is closed (no more data), this stage terminates processing.
// 3.1. This stage closes the outgoing channel.
// 3.2. This stage waits for the next stage's error channel. It can be nil.
// 3.3. The error is propagated back. If nil, do not send anything.
// 3.4. This stage closes the error channel.
// 3.5. This stage finishes all routines.
//
// 4. If an error is encountered, the error came from the next stage or this stage.
//
// 5. If the error originated in this stage:
// 5.1. This stage must stop processing data and writing to the outgoing channel.
// 5.2. This stage closes the outgoing channel.
// 5.3. This stage waits for the error signal from the next stage. It can aggregate it to its own.
// 5.4. This stage sends the (maybe aggregated) error to the previous stage.
// 5.5. This stage closes the error channel.
// 5.6. This stage finishes all routines.
//
// 6. If the error came from the next stage:
// 6.1. This stage must stop processing data, but it can't close its incoming channel.
// 6.2. This stage closes its outgoing channel.
// 6.2.1. This forces the next stage to stop processing.
// 6.2.2. Error or nil will be sent back. There was a previous error from the next stage.
// 6.3. This stage propagates backwards the error.
// 6.4. This stage closes its error channel.
// 6.5. This stage finishes all routines.
//
// Design:
//
// 1. The stage reads both the incoming and next stage's error channels _simultaneously_ (select{}).
//
// 2. If we read from the incoming channel, process data.
// 2.1. If no error processing, write to outgoing channel.
// 2.1.1. Write to the outgoing channel while also reading the next stage's error channel.
// 2.1.2. If success at writing to the outgoing channel, go to 1.
// 2.1.3. If an error was read during the attempt to write the data, go to 2.2.1.
//
// 2.2. If error processing:
// 2.2.1. Stop processing
// 2.2.2. Store this stage's error
// 2.2.3. Close outgoing channel.
// 2.3.4. Block the routine until the next stage has finished.
// 2.3.5. This means read from the error channel of the next stage.
// 2.3.6. Signal that this stage is done (e.g. done channel).
//
// 3. If we read something from the next stage's error channel:
// 3.1. Go to 2.2.1.
type Pipeline struct {
	linkFunc func(p *Pipeline)
	Ctx      context.Context // Running context.
	Stages   []StageLike
	Source   SourceLike
	Sink     SinkLike
}

func NewPipeline(
	linkFunc func(p *Pipeline),
	options ...pipelineOptions,
) (*Pipeline, error) {
	p := &Pipeline{
		linkFunc: linkFunc,
	}
	for _, opt := range options {
		opt(p)
	}

	// Check that the pipeline is conformant.
	err := p.check()

	return p, err
}

type pipelineOptions func(*Pipeline)

func WithStages(stages ...StageLike) pipelineOptions {
	return func(p *Pipeline) {
		stages := stages
		p.Stages = make([]StageLike, len(stages))
		copy(p.Stages, stages)
	}
}

func WithAutoResumeAtStage(
	targetStage int,
	shouldResumeNow func() bool,
	relink func(*Pipeline),
	affectedStages ...int,
) pipelineOptions {
	return func(p *Pipeline) {
		origLinkFunc := p.linkFunc
		// Sort the affected stages so that Resume can walk backwards.
		affectedStages := util.Qsort(affectedStages)

		p.linkFunc = func(p *Pipeline) {
			DebugPrintf("[autoresume] calling original link function\n")
			origLinkFunc(p)

			// Replace the target's error channel with a new one, but keep the original one open.
			// Every time the target sends a message to its error channel, forward it to the
			// original one (the one that the previous stage has linked).
			// But when the target closes its error channel, if shouldResumeNow indicates so,
			// create a new error channel and keep the same behavior as before.

			// Tag the target stage.
			target := p.Stages[targetStage]

			// Replace the salient error channel of the target stage.
			origErrCh := target.Base().ErrCh
			DebugPrintf("[autoresume] orig error channel: %s\n", chanPtr(origErrCh))
			newErrCh := make(chan error)
			target.Base().ErrCh = newErrCh
			DebugPrintf("[autoresume] new error channel: %s\n", chanPtr(newErrCh))

			go func() {
				for {
					for err := range newErrCh {
						DebugPrintf("[autoresume] err from target: %v\n", err)
						// Pass it along.
						origErrCh <- err
					}
					DebugPrintf("[autoresume] target error channel %s is closed\n",
						chanPtr(newErrCh))

					// The target closed the error channel, check whether to resume automatically.
					if !shouldResumeNow() {
						DebugPrintf("[autoresume] *************** closing sniffer error channel\n")
						// The function indicates not to resume, close the new error channel.
						close(origErrCh)
						// And exit, as once not resuming means stopping.
						return
					}

					DebugPrintf("[autoresume] request to resume: true. Affected stages: %v\n",
						affectedStages)
					// Auto resume was requested, prepare affected stages.
					for i := len(affectedStages) - 1; i >= 0; i-- {
						p.Stages[affectedStages[i]].Prepare(p.Ctx)
					}

					// The target stage needs a new error and stop channels.
					newErrCh = make(chan error)
					target.Base().ErrCh = newErrCh
					target.Base().StopCh = make(chan None)

					if sink, ok := target.(SinkLike); ok {
						sink.PrepareSink(p.Ctx)
					}
					DebugPrintf("[autoresume] stages prepared\n")

					relink(p)
					DebugPrintf("[autoresume] relink called\n")

					// Resume all affected and target stages.
					for i := len(affectedStages) - 1; i >= 0; i-- {
						p.Stages[affectedStages[i]].Resume(p.Ctx)
					}
					// Also the target stage.
					target.Resume(p.Ctx)
					DebugPrintf("[autoresume] stages resumed\n")
				}
			}()
		}
	}
}

func StageAtIndex[IN, OUT any](p *Pipeline, index int) *Stage[IN, OUT] {
	return p.Stages[index].(*Stage[IN, OUT])
}

func SourceStage[OUT any](p *Pipeline) *Stage[None, OUT] {
	return SourceAsStage(p.Stages[0].(*Source[OUT]))
}

func SinkStage[IN any](p *Pipeline) *Stage[IN, None] {
	return SinkAsStage(p.Stages[len(p.Stages)-1].(*Sink[IN]))
}

func (p *Pipeline) Resume(ctx context.Context) {
	p.Ctx = ctx
	p.prepare()
	p.linkFunc(p)
	// Now resume in reverse order
	for i := len(p.Stages) - 1; i >= 0; i-- {
		p.Stages[i].Resume(ctx)
	}
}

func (p *Pipeline) Wait(ctx context.Context) error {
	// The first stage is a source?
	if source, ok := p.Stages[0].(SourceLike); ok {
		DebugPrintf("[pipeline] Wait on a source, chan is: %s.\n",
			chanPtr(source.GetSourceBase().TopErrCh))
		return source.Wait(ctx)
	}

	// It is not a source, just treat it as a stage.
	DebugPrintf("[pipeline] Wait on NON source, chan is: %s.\n",
		chanPtr(p.Stages[0].Base().ErrCh))
	return <-p.Stages[0].Base().ErrCh
}

func (p *Pipeline) prepare() {
	for _, s := range p.Stages {
		s.Prepare(p.Ctx)
	}
}

// check finds the source and sink of this pipeline, or reports an error.
func (p *Pipeline) check() error {
	p.Source = nil
	for _, s := range p.Stages {
		if s, ok := s.(SourceLike); ok {
			p.Source = s
			break
		}
	}
	if p.Source == nil {
		return fmt.Errorf("no source in pipeline")
	}

	p.Sink = nil
	for _, s := range p.Stages {
		if s, ok := s.(SinkLike); ok {
			p.Sink = s
			break
		}
	}
	if p.Sink == nil {
		return fmt.Errorf("no sink in pipeline")
	}

	return nil
}
