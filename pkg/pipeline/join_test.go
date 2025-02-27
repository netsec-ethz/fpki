package pipeline

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/netsec-ethz/fpki/pkg/util/debug"
	"github.com/stretchr/testify/require"
)

// TestBasicJoinPipelines checks that joining two basic pipelines work.
func TestBasicJoinPipelines(t *testing.T) {
	defer PrintAllDebugLines()
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	// The pipelines are:
	// p1: A[int]->B->C[string]
	// p2: D[string]->E[string]

	p1SourceIndex := 0
	p1SinkCallCount := 0
	p1, err := NewPipeline(
		func(p *Pipeline) {
			// A -> B -> C
			a := SourceStage[int](p)
			b := StageAtIndex[int, string](p, 1)
			c := SinkStage[string](p)
			LinkStagesFanOut(a, b)
			LinkStagesFanOut(b, c)
		},
		WithStages(
			NewSource[int](
				"a",
				WithSequentialOutputs[None, int](),
				WithSourceFunction(func() ([]int, []int, error) {
					defer func() { p1SourceIndex++ }()
					inData := []int{1, 2, 3, 4, 5}
					if p1SourceIndex < len(inData) {
						DebugPrintf("[a] [TEST] source function called with %v\n", inData[p1SourceIndex])
						return inData[p1SourceIndex : p1SourceIndex+1], []int{0}, nil
					}
					return nil, nil, NoMoreData
				}),
			),
			NewStage[int, string](
				"b",
				WithSequentialOutputs[int, string](),
				WithProcessFunction(func(in int) ([]string, []int, error) {
					s := strconv.Itoa(in)
					return []string{s}, []int{0}, nil
				}),
			),
			NewSink[string](
				"c",
				WithSinkFunction(func(in string) error {
					DebugPrintf("[c] [TEST] sink function called with %v\n", in)
					p1SinkCallCount++
					return nil
				}),
			),
		),
	)
	require.NoError(t, err)

	p2GotValues := make([]string, 0)
	p2SourceCh := make(chan string)
	p2SourceCallCount := 0
	p2, err := NewPipeline(
		func(p *Pipeline) {
			// D -> E
			d := SourceStage[string](p)
			e := SinkStage[string](p)
			LinkStagesFanOut(d, e)
		},
		WithStages(
			NewSource[string](
				"d",
				WithSourceChannel(&p2SourceCh, func(in string) ([]int, error) {
					DebugPrintf("[d] [TEST] source channel processing called with %v\n", in)
					p2SourceCallCount++
					return []int{0}, nil
				}),
				WithSequentialOutputs[None, string](),
			),
			NewSink[string](
				"e",
				WithSinkFunction(func(in string) error {
					DebugPrintf("[e] [TEST] sink function called with %v\n", in)
					p2GotValues = append(p2GotValues, in)
					t.Logf("[e] received %s", in)
					return nil
				}),
				WithSequentialInputs[string, None](),
			),
		),
	)
	require.NoError(t, err)

	jointPipeline, err := JoinTwoPipelines[string](p1, p2)
	require.NoError(t, err)
	tests.TestOrTimeout(t, tests.WithTimeout(time.Second), func(t tests.T) {
		jointPipeline.Resume(ctx)
		err := jointPipeline.Wait(ctx)
		require.NoError(t, err)
	})
	require.Equal(t, []string{"1", "2", "3", "4", "5"}, p2GotValues)
	require.Equal(t, len(p2GotValues), p1SinkCallCount)
	require.Equal(t, len(p2GotValues), p2SourceCallCount)
}

// TestBasicJoinPipelines checks that joining two basic pipelines work.
func TestComplexJoinPipelines(t *testing.T) {
	defer PrintAllDebugLines()
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	// The pipelines are:
	// p1: A1[int] --> B1 --> D1[string]
	//              \_ C1 _/

	// p2: A2[string] --> B2 --> D2[string]
	//                 \_ C2 _/

	// The stage p1.D1 has auto resume enabled, to enact a bundle-size like behavior.
	// The bundle size is 3.

	// All inputs and outputs are sequential.

	p1SourceIndex := 0
	p1SinkCallCount := 0
	p1SinkOnNoMoreDataCalled := false
	p1, err := NewPipeline(
		func(p *Pipeline) {
			// A1[int] --> B1 --> D1[string]
			//          \_ C1 _/
			a := SourceStage[int](p)
			b := StageAtIndex[int, string](p, 1)
			c := StageAtIndex[int, string](p, 2)
			d := SinkStage[string](p)
			LinkStagesAt(a, 0, b, 0)
			LinkStagesAt(a, 1, c, 0)
			LinkStagesAt(b, 0, d, 0)
			LinkStagesAt(c, 0, d, 1)
		},
		WithStages(
			NewSource[int](
				"a1",
				WithMultiOutputChannels[None, int](2),
				WithSequentialOutputs[None, int](),
				WithSourceFunction(func() ([]int, []int, error) {
					defer func() { p1SourceIndex++ }()
					inData := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
					if p1SourceIndex < len(inData) {
						DebugPrintf("[a1] [TEST] source function called with %v\n",
							inData[p1SourceIndex])
						return inData[p1SourceIndex : p1SourceIndex+1],
							[]int{p1SourceIndex % 2},
							nil
					}
					return nil, nil, NoMoreData
				}),
			),
			NewStage[int, string](
				"b1",
				WithSequentialInputs[int, string](),
				WithSequentialOutputs[int, string](),
				WithProcessFunction(func(in int) ([]string, []int, error) {
					s := strconv.Itoa(in)
					time.Sleep(10 * time.Millisecond) // be slower than the other branch.
					return []string{s}, []int{0}, nil
				}),
			),
			NewStage[int, string](
				"c1",
				WithSequentialInputs[int, string](),
				WithSequentialOutputs[int, string](),
				WithProcessFunction(func(in int) ([]string, []int, error) {
					s := strconv.Itoa(in)
					return []string{s}, []int{0}, nil
				}),
			),
			NewSink[string](
				"d1",
				WithMultiInputChannels[string, None](2),
				WithSequentialInputs[string, None](),
				WithSinkFunction(func(in string) error {
					DebugPrintf("[d1] [TEST] sink function called with %v\n", in)
					p1SinkCallCount++
					if p1SinkCallCount%3 == 0 { // Bundle size reached.
						DebugPrintf("[d1] [TEST] bundle completed\n")
						return NoMoreData
					}
					return nil
				}),
				// TODO: desirable to automate not calling autoresume when no input.
				WithOnNoMoreData[string, None](func() ([]None, []int, error) {
					DebugPrintf("[d1] [TEST] OnNoMoreData() called\n")
					p1SinkOnNoMoreDataCalled = true
					return nil, nil, nil
				}),
			),
		),
		WithAutoResumeAtStage(
			3, // sink
			func() bool {
				DebugPrintf("[TEST] p1 shouldResumeNow() called, will return %v\n",
					!p1SinkOnNoMoreDataCalled)
				return !p1SinkOnNoMoreDataCalled
			},
			func(p *Pipeline) {
				// relink function, nothing to relink.
			},
			// no stages affected.
		),
	)
	require.NoError(t, err)

	p2SourceCh := make(chan string)
	p2SourceCallCount := 0
	p2SinkCallCount := 0
	p2GotValues := make([]int, 0)
	p2, err := NewPipeline(
		func(p *Pipeline) {
			// A2[string] --> B2 --> D2[int]
			//             \_ C2 _/
			a := SourceStage[string](p)
			b := StageAtIndex[string, int](p, 1)
			c := StageAtIndex[string, int](p, 2)
			d := SinkStage[int](p)
			LinkStagesAt(a, 0, b, 0)
			LinkStagesAt(a, 1, c, 0)
			LinkStagesAt(b, 0, d, 0)
			LinkStagesAt(c, 0, d, 1)
		},
		WithStages(
			NewSource[string](
				"a2",
				WithSourceChannel(&p2SourceCh, func(in string) ([]int, error) {
					defer func() { p2SourceCallCount++ }()
					return []int{p2SourceCallCount % 2}, nil
				}),
				WithMultiOutputChannels[None, string](2),
				WithSequentialOutputs[None, string](),
			),
			NewStage[string, int](
				"b2",
				WithProcessFunction(func(in string) ([]int, []int, error) {
					i, err := strconv.Atoi(in)
					return []int{i}, []int{0}, err
				}),
				WithSequentialInputs[string, int](),
				WithSequentialOutputs[string, int](),
			),
			NewStage[string, int](
				"c2",
				WithProcessFunction(func(in string) ([]int, []int, error) {
					i, err := strconv.Atoi(in)
					return []int{i}, []int{0}, err
				}),
				WithSequentialInputs[string, int](),
				WithSequentialOutputs[string, int](),
			),
			NewSink[int](
				"d2",
				WithSinkFunction(func(in int) error {
					DebugPrintf("[d2] [TEST] sink function called with %v\n", in)
					p2SinkCallCount++
					p2GotValues = append(p2GotValues, in)
					return nil
				}),
				WithMultiInputChannels[int, None](2),
				WithSequentialInputs[int, None](),
			),
		),
	)
	require.NoError(t, err)

	jointPipeline, err := JoinTwoPipelines[string](p1, p2)
	require.NoError(t, err)
	tests.TestOrTimeout(t, tests.WithTimeout(time.Second), func(t tests.T) {
		jointPipeline.Resume(ctx)
		err := jointPipeline.Wait(ctx)
		require.NoError(t, err)
	})
	require.Equal(t, []int{1, 2, 3, 5, 4, 6, 7, 8, 9, 10}, p2GotValues)
	require.Equal(t, len(p2GotValues), p1SinkCallCount)
	require.Equal(t, len(p2GotValues), p2SourceCallCount)
}

func TestChannelReferenceCaptures(t *testing.T) {
	t.Run("capture", func(t *testing.T) {
		t.Parallel()
		// Capturing the channel inside the goroutine does not make a local copy of the reference.
		// This means that at the time when the goroutine uses the channel, it could have changed.
		goNowCh := make(chan struct{}) // unblock goroutine
		inputCh := make(chan int)
		testOkCh := make(chan struct{})
		testFailCh := make(chan struct{})

		go func() {
			<-goNowCh

			t.Logf("[goroutine] original: %s", debug.Chan2str(inputCh))
			select {
			case in := <-inputCh:
				t.Logf("[goroutine] read from inputCh(%s): %v", debug.Chan2str(inputCh), in)
				testOkCh <- struct{}{}
			case <-time.After(50 * time.Millisecond):
				testFailCh <- struct{}{} // inputCh should point to the new channel.
			}
		}()
		t.Logf("[TEST] original: %s", debug.Chan2str(inputCh))
		inputCh = make(chan int, 1)
		t.Logf("[TEST] new: %s", debug.Chan2str(inputCh))
		goNowCh <- struct{}{}
		inputCh <- 1
		select {
		case <-testOkCh:
		case <-testFailCh:
			t.Fatal("failed: goroutine did not behave as expected")
		}
	})

	t.Run("local_copy", func(t *testing.T) {
		t.Parallel()
		// A local copy of the captured channel ensures that the channel doesn't change,
		// regardless of changes to the original reference that was captured.
		goNowCh := make(chan int) // unblock setup
		inputCh := make(chan int)
		testOkCh := make(chan struct{})
		testFailCh := make(chan struct{})

		go func() {
			// If we copy the reference, the change outside is not visible here.
			t.Logf("[goroutine] original: %s", debug.Chan2str(inputCh))
			inputCh := inputCh
			t.Logf("[goroutine] copy: %s", debug.Chan2str(inputCh))
			goNowCh <- 1 // goroutine ready
			i := <-goNowCh
			require.Equal(t, 2, i)

			select {
			case in := <-inputCh:
				t.Logf("[goroutine] read from inputCh(%s): %v", debug.Chan2str(inputCh), in)
				testFailCh <- struct{}{} // inputCh should point to the old channel.
			case <-time.After(50 * time.Millisecond):
				testOkCh <- struct{}{}
			}
		}()

		// Replace channel in the reference "inputCh"
		t.Logf("[TEST] original: %s", debug.Chan2str(inputCh))
		i := <-goNowCh // wait until the goroutine is running.
		require.Equal(t, 1, i)
		inputCh = make(chan int, 1)
		t.Logf("[TEST] new: %s", debug.Chan2str(inputCh))
		goNowCh <- 2
		inputCh <- 1
		select {
		case <-testOkCh:
		case <-testFailCh:
			t.Fatal("failed: goroutine did not behave as expected")
		}
	})

	t.Run("argument", func(t *testing.T) {
		t.Parallel()
		// A local copy of the captured channel ensures that the channel doesn't change,
		// regardless of changes to the original reference that was captured.
		goNowCh := make(chan int) // unblock setup
		inputCh := make(chan int)
		testOkCh := make(chan struct{})
		testFailCh := make(chan struct{})

		go func(inputCh chan int) {
			goNowCh <- 1   // signal ready
			i := <-goNowCh // wait for main to be ready
			require.Equal(t, 2, i)

			t.Logf("[goroutine] parameter: %s", debug.Chan2str(inputCh))
			select {
			case in := <-inputCh:
				t.Logf("[goroutine] read from inputCh(%s): %v", debug.Chan2str(inputCh), in)
				testFailCh <- struct{}{} // inputCh should point to the old channel.
			case <-time.After(50 * time.Millisecond):
				testOkCh <- struct{}{}
			}
		}(inputCh)

		// Replace channel in the reference "inputCh"
		t.Logf("[TEST] original: %s", debug.Chan2str(inputCh))
		i := <-goNowCh // wait until the goroutine is running.
		require.Equal(t, 1, i)
		inputCh = make(chan int, 1)
		t.Logf("[TEST] new: %s", debug.Chan2str(inputCh))
		goNowCh <- 2 // signal ready
		inputCh <- 1
		select {
		case <-testOkCh:
		case <-testFailCh:
			t.Fatal("failed: goroutine did not behave as expected")
		}
	})
}
