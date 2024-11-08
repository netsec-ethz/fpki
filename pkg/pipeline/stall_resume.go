package pipeline

import (
	"sync"

	"github.com/netsec-ethz/fpki/pkg/util"
)

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

// WithStallStages allows to temporarily stop (stall) stages, given a function that is evaluated at some
// stages. The stages to stall can overlap the stages where the function is evaluated.
// Finally, when the indicated stages are stalled, the whenStalled function is called.
// There can be several concurrent calls to the shouldStallPipeline evaluation function,
// but only one to whenStalled.
// Finally, the evaluation is done on the indicated stages, even before receiving data, while
// the execution of whenStalled is done on a separate goroutine, as soon as all pertinent
// stages are out of their processing function (not waiting for output to be sent).
func WithStallStages(
	stallTheseStages []StageLike,
	whenStalled func(),
	shouldStallPipeline func(StageLike) bool,
	evaluateAt []StageLike,
) pipelineOptions {

	// Mutex that all stages in evaluateAt and stallTheseStages need to acquire.
	// If acquired by an evaluate stage, and the evaluation returns true, the mutex is only
	// released after calling the whenStalled function.
	stallMu := sync.Mutex{}

	// Barrier for the stages in stallTheseStages when they are working. All stages must reach
	// the barrier before the whenStalled function to be called.
	workingStagesWg := sync.WaitGroup{}
	// This mutex is necessary to avoid adding workers while waiting for them to finish.
	workingStagesWgMu := sync.Mutex{}

	// The option modifies the onBeforeData callback of the stages in evaluatedAt, and the
	// onBeforeData and onProcessed callbacks of the stages in stallTheseStages.
	return func(p *Pipeline) {
		for _, s := range evaluateAt {
			s := s

			// Save the previous onBeforeData function.
			prevOnBeforeData := s.Base().onBeforeData

			s.Base().onBeforeData = func() {
				// Call the previous onBeforeData.
				prevOnBeforeData()

				// Evaluate iff initially we are not stalling.
				DebugPrintf("[%s] [stall] evaluating stall\n", s.Base().Name)
				stallMu.Lock()
				stall := shouldStallPipeline(s)
				DebugPrintf("[%s] [stall] should we stall? %v\n", s.Base().Name, stall)

				// Indicate to stall the pipeline if should stall and this is the first time.
				if stall {
					DebugPrintf("[%s] [stall] [stall-releaser] this stage will stall the pipeline\n", s.Base().Name)
					// Run in separate goroutine, to avoid blocking this stage if it is also
					// part of the stallTheseStages.
					go func() {
						// Wait for all to stall.
						DebugPrintf("[%s] [stall-releaser] waiting to get the working group\n", s.Base().Name)
						workingStagesWgMu.Lock()
						defer workingStagesWgMu.Unlock()
						DebugPrintf("[%s] [stall-releaser] waiting for stages to stall\n", s.Base().Name)
						workingStagesWg.Wait()
						DebugPrintf("[%s] [stall-releaser] all stages have stalled\n", s.Base().Name)

						// Execute whenStalled()
						whenStalled()

						// Resume the stalled stages.
						DebugPrintf("[%s] [stall-releaser] signaling stages to continue\n", s.Base().Name)
						stallMu.Unlock()
					}()
				} else {
					stallMu.Unlock()
				}

				DebugPrintf("[%s] [stall] out of evaluation\n", s.Base().Name)
			}
		}

		for _, s := range stallTheseStages {
			s := s

			// Simply try to obtain the mutex stallMu.
			prevOnBeforeData := s.Base().onBeforeData
			s.Base().onBeforeData = func() {
				// Call the previous onBeforeData.
				prevOnBeforeData()

				// Acquire the mutex, will have to wait if stalling.
				DebugPrintf("[%s] [stall] before mutex\n", s.Base().Name)
				stallMu.Lock()
				// Release it immediately, we have serialized the stages using the mutex.
				defer func() {
					stallMu.Unlock()
					defer DebugPrintf("[%s] [stall] out of maybe stalling\n", s.Base().Name)
				}()
			}

			prevOnReceivedData := s.Base().onReceivedData
			s.Base().onReceivedData = func() {
				// Call previous.
				prevOnReceivedData()

				// Indicate that this stage is about to start working.
				DebugPrintf("[%s] [stall] worker waiting to get the group\n", s.Base().Name)
				workingStagesWgMu.Lock()
				defer workingStagesWgMu.Unlock()

				DebugPrintf("[%s] [stall] adding an individual to the working group\n", s.Base().Name)
				workingStagesWg.Add(1)
			}

			prevOnProcessed := s.Base().onProcessed
			s.Base().onProcessed = func() {
				// Call previous.
				prevOnProcessed()

				// Indicate that this stage has finished working.
				DebugPrintf("[%s] [stall] removing one individual from the working group\n", s.Base().Name)
				workingStagesWg.Done()
			}
		}
	}
}
