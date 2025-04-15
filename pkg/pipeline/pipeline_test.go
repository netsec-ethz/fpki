package pipeline

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/netsec-ethz/fpki/pkg/tests/random"
	"github.com/stretchr/testify/require"
)

func TestSimple(t *testing.T) {
	defer PrintAllDebugLines()
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	// Prepare test.
	gotValues := []int{}

	p, err := NewPipeline(
		func(p *Pipeline) {
			// A -> B -> C
			a := SourceStage[int](p)
			b := StageAtIndex[int, int](p, 1)
			c := SinkStage[int](p)

			LinkStagesFanOut(a, b)
			LinkStagesFanOut(b, c)
		},
		WithStages(
			NewSource[int](
				"a",
				WithSourceSlice(&[]int{1, 2, 3, 4}, func(int) (int, error) {
					return 0, nil
				}),
				WithSequentialOutputs[None, int](),
			),
			NewStage[int, int](
				"b",
				WithProcessFunction(func(in int) ([]int, []int, error) {
					return []int{in + 1}, []int{0}, nil
				}),
				WithSequentialOutputs[int, int](),
				WithSequentialInputs[int, int](),
			),
			NewSink[int](
				"c",
				WithSinkFunction(func(in int) error {
					gotValues = append(gotValues, in)
					return nil
				}),
				WithSequentialInputs[int, None](),
			),
		),
	)
	require.NoError(t, err)

	tests.TestOrTimeout(t, tests.WithTimeout(time.Second), func(t tests.T) {
		p.Resume(ctx)
		err := p.Wait(ctx)
		require.NoError(t, err)
	})
	require.Equal(t, []int{2, 3, 4, 5}, gotValues)
}

func TestSimpleAllSequential(t *testing.T) {
	defer PrintAllDebugLines()
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	// Prepare test.
	gotValues := []int{}

	p, err := NewPipeline(
		func(p *Pipeline) {
			// A -> B -> C
			a := SourceStage[int](p)
			b := StageAtIndex[int, int](p, 1)
			c := SinkStage[int](p)

			LinkStagesFanOut(a, b)
			LinkStagesFanOut(b, c)
		},
		WithStages(
			NewSource[int](
				"a",
				WithSourceSlice(&[]int{1, 2, 3, 4}, func(int) (int, error) {
					return 0, nil
				}),
				WithSequentialOutputs[None, int](),
			),
			NewStage[int, int](
				"b",
				WithProcessFunction(func(in int) ([]int, []int, error) {
					return []int{in + 1}, []int{0}, nil
				}),
				WithSequentialOutputs[int, int](),
				WithSequentialInputs[int, int](),
			),
			NewSink[int](
				"c",
				WithSinkFunction(func(in int) error {
					gotValues = append(gotValues, in)
					return nil
				}),
				WithSequentialInputs[int, None](),
			),
		),
	)
	require.NoError(t, err)

	tests.TestOrTimeout(t, tests.WithTimeout(time.Second), func(t tests.T) {
		p.Resume(ctx)
		err := p.Wait(ctx)
		require.NoError(t, err)
	})
	require.Equal(t, []int{2, 3, 4, 5}, gotValues)
}

func TestPipeline(t *testing.T) {
	defer PrintAllDebugLines()
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	// Prepare test.
	gotValues := make([]int, 0)
	incomingValues := []int{1, 2, 3}
	firstTimeErrorAtB := true

	// Create pipeline.
	p, err := NewPipeline(
		func(p *Pipeline) {
			// A->B->C
			a := p.Stages[0].(*Source[int])
			b := p.Stages[1].(*Stage[int, int])
			c := p.Stages[2].(*Sink[int])

			LinkStagesFanOut(SourceAsStage(a), b)
			LinkStagesFanOut(b, SinkAsStage(c))
		},
		WithStages(
			NewSource[int](
				"a",
				WithSourceSlice(&incomingValues, func(in int) (int, error) {
					DebugPrintf("[a] [TEST] source sends %v\n", in)
					return 0, nil
				}),
				WithSequentialOutputs[None, int](),
			),
			NewStage[int, int](
				"b",
				WithProcessFunction(func(in int) ([]int, []int, error) {
					// This b stage fails when it receives a 4.
					var err error
					if in == 2 && firstTimeErrorAtB {
						firstTimeErrorAtB = false
						DebugPrintf("[b] [TEST] emitting ERROR\n")
						// return nil, nil, fmt.Errorf("error at stage b")
						err = fmt.Errorf("error at stage b")
					}
					return []int{in + 1}, []int{0}, err
				}),
				WithSequentialOutputs[int, int](),
			),
			NewSink[int](
				"c",
				WithSinkFunction(func(in int) error {
					gotValues = append(gotValues, in)
					DebugPrintf("[c] [TEST] got %d\n", in)
					return nil
				}),
			),
		),
	)
	require.NoError(t, err)

	// Resume all stages. There is nobody reading the last channel, so the pipeline will stall.
	tests.TestOrTimeout(t, tests.WithTimeout(time.Second), func(t tests.T) {
		p.Resume(ctx)
		err := p.Wait(ctx)
		DebugPrintf("[TEST] error 1: %v\n", err)
		require.Error(t, err)
	})
	require.Equal(t, []int{2}, gotValues)

	// Check pipelines have been closed.
	a := p.Stages[0].(*Source[int])
	b := p.Stages[1].(*Stage[int, int])
	c := p.Stages[2].(*Sink[int])
	checkClosed(t, a.ErrCh)
	checkClosed(t, b.ErrCh)
	checkClosed(t, c.ErrCh)
	checkClosed(t, a.StopCh)
	checkClosed(t, b.StopCh)
	checkClosed(t, c.StopCh)
	checkAllClosed(t, a.IncomingChs)
	checkAllClosed(t, b.IncomingChs)
	checkAllClosed(t, c.IncomingChs)
	checkAllClosed(t, a.OutgoingChs)
	checkAllClosed(t, b.OutgoingChs)
	checkAllClosed(t, c.OutgoingChs)
	checkAllClosed(t, a.NextErrChs)
	checkAllClosed(t, b.NextErrChs)
	checkAllClosed(t, c.NextErrChs)

	incomingValues = incomingValues[len(gotValues):]

	// We can now resume.
	DebugPrintf("------------------------ RESUMING ----------------------\n")
	tests.TestOrTimeout(t, tests.WithTimeout(time.Second), func(t tests.T) {
		p.Resume(ctx)
		err := p.Wait(ctx)
		require.NoError(t, err)
	})
	require.Equal(t, []int{2, 3, 4}, gotValues)

	// Check pipelines have been closed.
	a = p.Stages[0].(*Source[int])
	b = p.Stages[1].(*Stage[int, int])
	c = p.Stages[2].(*Sink[int])
	checkClosed(t, a.ErrCh)
	checkClosed(t, b.ErrCh)
	checkClosed(t, c.ErrCh)
	checkClosed(t, a.StopCh)
	checkClosed(t, b.StopCh)
	checkClosed(t, c.StopCh)
	checkAllClosed(t, a.IncomingChs)
	checkAllClosed(t, b.IncomingChs)
	checkAllClosed(t, c.IncomingChs)
	checkAllClosed(t, a.OutgoingChs)
	checkAllClosed(t, b.OutgoingChs)
	checkAllClosed(t, c.OutgoingChs)
	checkAllClosed(t, a.NextErrChs)
	checkAllClosed(t, b.NextErrChs)
	checkAllClosed(t, c.NextErrChs)
}

// TestSourceWithChannel creates a pipeline that has a source based on a channel.
func TestSourceWithChannel(t *testing.T) {
	defer PrintAllDebugLines()
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	// Prepare test.
	gotValues := make([]int, 0)
	incomingIndex := 0
	incomingCh := make(chan int)
	go func() {
		inData := []int{1, 2, 3, 4}
		for _, in := range inData {
			incomingCh <- in
		}
		close(incomingCh)
	}()

	p, err := NewPipeline(
		func(p *Pipeline) {
			// Link function.
			// A -> B -> D
			//   \_ C _/
			a := SourceStage[int](p)
			b := StageAtIndex[int, int](p, 1)
			c := StageAtIndex[int, int](p, 2)
			d := SinkStage[int](p)

			LinkStagesAt(a, 0, b, 0)
			LinkStagesAt(a, 1, c, 0)
			LinkStagesAt(b, 0, d, 0)
			LinkStagesAt(c, 0, d, 1)
		},
		WithStages(
			NewSource(
				"a",
				WithMultiOutputChannels[None, int](2),
				WithSequentialOutputs[None, int](),
				WithSourceChannel(
					&incomingCh,
					func(in int) ([]int, error) {
						defer func() { incomingIndex++ }()
						return []int{incomingIndex % 2}, nil
					},
				),
			),
			NewStage(
				"b",
				WithProcessFunction(func(in int) ([]int, []int, error) {
					return []int{in + 10}, []int{0}, nil
				}),
			),
			NewStage(
				"c",
				WithProcessFunction(func(in int) ([]int, []int, error) {
					return []int{in + 20}, []int{0}, nil
				}),
			),
			NewSink(
				"d",
				WithMultiInputChannels[int, None](2),
				WithSequentialInputs[int, None](),
				WithSinkFunction(func(in int) error {
					gotValues = append(gotValues, in)
					return nil
				}),
			),
		),
	)
	require.NoError(t, err)

	tests.TestOrTimeout(t, tests.WithTimeout(time.Second), func(t tests.T) {
		p.Resume(ctx)
		err := p.Wait(ctx)
		require.NoError(t, err)
	})
	require.Equal(t, []int{11, 22, 13, 24}, gotValues)
}

func TestStop(t *testing.T) {
	defer PrintAllDebugLines()
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	// Prepare test.
	incomingCh := make(chan int)
	go func() { // infinite loop sending 1 to source.
		for {
			incomingCh <- 1
		}
	}()

	gotValues := make([]int, 0)
	processedAtBcount := 0
	stopB := sync.WaitGroup{}
	stopB.Add(1) // The test waits until b tells it to stop the pipeline.

	// Create pipeline.
	p, err := NewPipeline(
		func(p *Pipeline) {
			// A->B->C
			a := p.Stages[0].(*Source[int])
			b := p.Stages[1].(*Stage[int, int])
			c := p.Stages[2].(*Sink[int])

			LinkStagesFanOut(SourceAsStage(a), b)
			LinkStagesFanOut(b, SinkAsStage(c))
		},
		WithStages(
			NewSource[int](
				"a",
				WithSourceChannel(&incomingCh, func(in int) ([]int, error) {
					return []int{0}, nil
				}),
			),
			NewStage[int, int](
				"b",
				WithProcessFunction(func(in int) ([]int, []int, error) {
					defer func() { processedAtBcount++ }()
					if processedAtBcount == 10 {
						stopB.Done()
					}
					return []int{in + 1}, []int{0}, nil
				}),
			),
			NewSink[int](
				"c",
				WithSinkFunction(func(in int) error {
					DebugPrintf("[TEST] got %d\n", in)
					gotValues = append(gotValues, in)
					return nil
				}),
			),
		),
	)
	require.NoError(t, err)

	// Resume all stages. There is nobody reading the last channel, so the pipeline will stall.
	p.Resume(ctx)
	// Wait to stop the pipeline in the middle of the process.
	stopB.Wait()
	err = StageAtIndex[int, int](p, 1).StopAndWait()
	require.NoError(t, err)
	require.LessOrEqual(t, 10, len(gotValues))
}

func TestBundleSize(t *testing.T) {
	defer PrintAllDebugLines()
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	// Prepare test.
	inValues := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	// sourceValue := 0
	bundleSize := 4
	processedAtBcount := 0
	gotValues := make([]int, 0)

	// Create pipeline.
	p, err := NewPipeline(
		func(p *Pipeline) {
			// A->B->C
			a := p.Stages[0].(*Source[int])
			b := p.Stages[1].(*Stage[int, int])
			c := p.Stages[2].(*Sink[int])

			LinkStagesFanOut(SourceAsStage(a), b)
			LinkStagesFanOut(b, SinkAsStage(c))
		},
		WithStages(
			NewSource[int](
				"a",
				WithSourceSlice(&inValues, func(int) (int, error) {
					return 0, nil
				}),
			),
			NewStage[int, int](
				"b",
				WithProcessFunction(func(in int) ([]int, []int, error) {
					processedAtBcount++
					var err error
					if processedAtBcount%bundleSize == 0 {
						err = NoMoreData
					}
					return []int{in + 10}, []int{0}, err
				}),
			),
			NewSink[int](
				"c",
				WithSinkFunction(func(in int) error {
					DebugPrintf("[TEST] got %d\n", in)
					gotValues = append(gotValues, in)
					return nil
				}),
			),
		),
	)
	require.NoError(t, err)

	// Resume all stages. There is nobody reading the last channel, so the pipeline will stall.
	tests.TestOrTimeout(t, tests.WithTimeout(time.Second), func(t tests.T) {
		p.Resume(ctx)
		// Wait to stop the pipeline in the middle of the process.
		err := p.Wait(ctx)
		require.NoError(t, err)
		require.Equal(t, bundleSize, len(gotValues))
	})
	// Check that the values were inserted in the correct order.
	require.Equal(t, []int{11, 12, 13, 14}, gotValues)

	inValues = inValues[len(gotValues):]

	// Continue processing one more bundle.
	tests.TestOrTimeout(t, tests.WithTimeout(time.Second), func(t tests.T) {
		DebugPrintf("---------------- RESUMING ----------------\n")
		p.Resume(ctx)
		err := p.Wait(ctx)
		require.NoError(t, err)
		require.Equal(t, 2*bundleSize, len(gotValues))
		// The value 4 broke the processing at B, but if A called the process function and
		// failed to send the value, its OnErrorSending function will rewind the index.
		// We thus expect sequential values always.
		require.Equal(t, []int{11, 12, 13, 14, 15, 16, 17, 18}, gotValues)
	})
	DebugPrintf("---------------- FINISHED ----------------\n")
}

func TestMultiChannel(t *testing.T) {
	defer PrintAllDebugLines()
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	// Prepare test.
	gotValues := make([]int, 0)
	currentIndex := 0

	// Create pipeline.
	p, err := NewPipeline(
		func(p *Pipeline) {
			// 1->2->3->4
			//     \__/
			s1 := p.Stages[0].(*Source[int])
			s2 := p.Stages[1].(*Stage[int, int])
			s3 := p.Stages[2].(*Stage[int, int])
			s4 := p.Stages[3].(*Sink[int])

			LinkStagesFanOut(SourceAsStage(s1), s2)
			LinkStagesAt(s2, 0, s3, 0)
			LinkStagesAt(s2, 1, SinkAsStage(s4), 0)
			LinkStagesAt(s3, 0, SinkAsStage(s4), 1)
		},
		WithStages(
			NewSource[int](
				"1", // source.
				WithSourceFunction(func() ([]int, []int, error) {
					// As a source of data.
					inData := []int{1, 2, 3}
					DebugPrintf("[TEST] source index %d\n", currentIndex)
					if currentIndex >= len(inData) {
						return nil, nil, NoMoreData
					}
					defer func() { currentIndex++ }()
					return inData[currentIndex : currentIndex+1], []int{0}, nil
				}),
			),
			// Stage 2 has two output channels, to 3 and to 4.
			NewStage[int, int](
				"2", // adds 1.
				WithProcessFunction(func(in int) ([]int, []int, error) {
					return []int{in + 1, in + 1}, []int{0, 1}, nil
				}),
				WithMultiOutputChannels[int, int](2), // to 3 and 4
			),
			NewStage[int, int](
				"3", // multiply by 2.
				WithProcessFunction(func(in int) ([]int, []int, error) {
					return []int{in * 2}, []int{0}, nil
				}),
			),
			NewSink[int](
				"4", // sink.
				WithSinkFunction(func(in int) error {
					gotValues = append(gotValues, in)
					DebugPrintf("[TEST] got %d\n", in)
					return nil
				}),
				WithMultiInputChannels[int, None](2),
			),
		),
	)
	require.NoError(t, err)

	// Resume all stages. There is nobody reading the last channel, so the pipeline will stall.
	tests.TestOrTimeout(t, tests.WithTimeout(time.Second), func(t tests.T) {
		p.Resume(ctx)
		err := p.Wait(ctx)
		DebugPrintf("[TEST] error 1: %v\n", err)
		require.NoError(t, err)
	})
}

func TestMultipleOutputs(t *testing.T) {
	defer PrintAllDebugLines()
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	// Prepare test.
	gotValues := make([]int, 0)
	currentIndex := 0

	// Create pipeline.
	p, err := NewPipeline(
		func(p *Pipeline) {
			// A->B->C
			a := p.Stages[0].(*Source[int])
			b := p.Stages[1].(*Stage[int, int])
			c := p.Stages[2].(*Sink[int])

			LinkStagesFanOut(SourceAsStage(a), b)
			LinkStagesFanOut(b, SinkAsStage(c))
		},
		WithStages(
			NewSource[int](
				"a",
				WithSourceFunction(func() ([]int, []int, error) {
					// As a source of data.
					inData := []int{1, 2, 3}
					DebugPrintf("[TEST] source index %d\n", currentIndex)
					if currentIndex >= len(inData) {
						return nil, nil, NoMoreData
					}
					defer func() { currentIndex++ }()
					return inData[currentIndex : currentIndex+1], []int{0}, nil
				}),
			),
			NewStage[int, int](
				"b",
				WithProcessFunction(func(in int) ([]int, []int, error) {
					return []int{in, in + 1}, []int{0, 0}, nil
				}),
			),
			NewSink[int](
				"c",
				WithSinkFunction(func(in int) error {
					DebugPrintf("[TEST] got %d\n", in)
					gotValues = append(gotValues, in)
					return nil
				}),
			),
		),
	)
	require.NoError(t, err)

	// Resume all stages. There is nobody reading the last channel, so the pipeline will stall.
	tests.TestOrTimeout(t, tests.WithTimeout(time.Second), func(t tests.T) {
		p.Resume(ctx)
		// Wait to stop the pipeline in the middle of the process.
		err := p.Wait(ctx)
		require.NoError(t, err)
	})
	require.ElementsMatch(t, []int{1, 2, 2, 3, 3, 4}, gotValues)
}

// TestSingleOutputMultiInput checks that multiple stages sending input to one stage X, which only
// has one output, and which sends to multiple stages, work as expected.
// This X stage can be seen as a "collector" or "load-distributor" for data, that is spread out
// to the first available stage that reads it.
func TestSingleOutputMultiInput(t *testing.T) {
	defer PrintAllDebugLines()
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	// Prepare test.
	initialValues := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	gotValues := make([]int, 0)

	p, err := NewPipeline(
		func(p *Pipeline) {
			// Link function.
			// a --> b1 --> c
			//   |-> b2 --|
			//
			// But "a" has only _ONE_ output channel.

			a := SourceStage[int](p)
			b1 := StageAtIndex[int, int](p, 1)
			b2 := StageAtIndex[int, int](p, 2)
			c := SinkStage[int](p)

			LinkStagesDistribute(a, b1, b2)
			LinkStagesAt(b1, 0, c, 0)
			LinkStagesAt(b2, 0, c, 1)
		},
		WithStages(
			NewSource[int](
				"a",
				WithSourceSlice(&initialValues, func(in int) (int, error) {
					return 0, nil
				}),
			),
			NewStage(
				"b1",
				WithProcessFunction(func(in int) ([]int, []int, error) {
					time.Sleep(10 * time.Millisecond)
					return []int{in + 10}, []int{0}, nil
				}),
			),
			NewStage(
				"b2",
				WithProcessFunction(func(in int) ([]int, []int, error) {
					time.Sleep(10 * time.Millisecond)
					return []int{in + 20}, []int{0}, nil
				}),
			),
			NewSink(
				"c",
				WithMultiInputChannels[int, None](2),
				WithSinkFunction(func(in int) error {
					gotValues = append(gotValues, in)
					return nil
				}),
			),
		),
	)
	require.NoError(t, err)

	tests.TestOrTimeout(t, tests.WithContext(ctx), func(t tests.T) {
		p.Resume(ctx)
		err = p.Wait(ctx)
	})
	require.NoError(t, err)

	// Final values. We don't know the exact distribution of the data along b1 and b2, but
	// we should see values going through both of them.
	t.Logf("values = %v", gotValues)
	tests.CheckAnyIsTrue(t, gotValues, func(t tests.T, v int) bool {
		return v < 21 // went thru b1
	})
	tests.CheckAnyIsTrue(t, gotValues, func(t tests.T, v int) bool {
		return v > 20 // went thru b2
	})
}

func TestLinkStagesCrissCross(t *testing.T) {
	defer PrintAllDebugLines()
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	// Prepare test.
	initialValues := []int{1, 2, 3, 4, 5, 6, 7, 8}
	gotValues1 := make([]int, 0)
	gotValues2 := make([]int, 0)

	p, err := NewPipeline(
		func(p *Pipeline) {
			// Link function.
			//	a ─┬─> b1 ─┬─> c1
			//	   └─> b2 ─┴─> c2
			// But there is only _ONE_ input-output channel between aN and bN.

			a := SourceStage[int](p)
			b1 := StageAtIndex[int, int](p, 1)
			b2 := StageAtIndex[int, int](p, 2)
			c1 := SinkStage[int](p)
			c2 := SinkStage[int](p)

			LinkStagesDistribute(a, b1, b2)
			LinkStagesCrissCross(
				[]*Stage[int, int]{b1, b2},
				[]*Stage[int, None]{c1, c2},
			)
		},
		WithStages(
			NewSource[int](
				"a",
				WithSourceSlice(&initialValues, func(in int) (int, error) {
					return 0, nil
				}),
			),
			NewStage( // adds 0
				"b1",
				WithProcessFunction(func(in int) ([]int, []int, error) {
					time.Sleep(10 * time.Millisecond)
					return []int{in}, []int{0}, nil
				}),
			),
			NewStage( // adds 10
				"b2",
				WithProcessFunction(func(in int) ([]int, []int, error) {
					time.Sleep(10 * time.Millisecond)
					return []int{in + 10}, []int{0}, nil
				}),
			),
			NewSink( // adds 100
				"c1",
				WithSinkFunction(func(in int) error {
					time.Sleep(15 * time.Millisecond)
					gotValues1 = append(gotValues1, in+100)
					return nil
				}),
			),
			NewSink( // adds 1000
				"c2",
				WithSinkFunction(func(in int) error {
					time.Sleep(15 * time.Millisecond)
					gotValues2 = append(gotValues2, in+1000)
					return nil
				}),
			),
		),
	)
	require.NoError(t, err)

	tests.TestOrTimeout(t, tests.WithContext(ctx), func(t tests.T) {
		p.Resume(ctx)
		err = p.Wait(ctx)
	})
	require.NoError(t, err)

	// Final values. We don't know the exact distribution of the data along b1, b2, c1, and c2,
	// but we should see values going through both of them.
	t.Logf("values1 = %v", gotValues1)
	t.Logf("values2 = %v", gotValues2)
	// Check all values at sink c1.
	tests.CheckAllAreTrue(t, gotValues1, func(t tests.T, v int) bool {
		return v < 1000 && v > 100
	})
	// Check all values at sink c2.
	tests.CheckAllAreTrue(t, gotValues1, func(t tests.T, v int) bool {
		return v > 1000
	})

	// Collate all values.
	allValues := append(gotValues1, gotValues2...)
	// Check some went thru b1.
	tests.CheckAnyIsTrue(t, allValues, func(t tests.T, v int) bool {
		v = v % 100
		return v < 10 // didn't add anything to tens.
	})
	// Check some went thru b2.
	tests.CheckAnyIsTrue(t, allValues, func(t tests.T, v int) bool {
		v = v % 100
		return v > 10 // added 10 to the value.
	})
}

func TestOnNoMoreData(t *testing.T) {
	defer PrintAllDebugLines()
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	// Prepare test.
	gotValues := make([]int, 0)
	currentIndex := 0
	bufferForB := make([]int, 0, 2048)
	outIndexesForB := make([]int, 0, len(bufferForB))

	// Create pipeline.
	p, err := NewPipeline(
		func(p *Pipeline) {
			// A->B->C
			// B keeps a preallocated buffer elements.
			a := p.Stages[0].(*Source[int])
			b := p.Stages[1].(*Stage[int, int])
			c := p.Stages[2].(*Sink[int])

			LinkStagesFanOut(SourceAsStage(a), b)
			LinkStagesFanOut(b, SinkAsStage(c))
		},
		WithStages(
			NewSource[int](
				"a",
				WithSourceFunction(func() ([]int, []int, error) {
					// As a source of data.
					inData := []int{1, 2, 3}
					DebugPrintf("[TEST] source index %d\n", currentIndex)
					if currentIndex >= len(inData) {
						return nil, nil, NoMoreData
					}
					defer func() { currentIndex++ }()
					return inData[currentIndex : currentIndex+1], []int{0}, nil
				}),
			),
			NewStage[int, int](
				"b",
				WithProcessFunction(func(in int) ([]int, []int, error) {
					bufferForB = append(bufferForB, in)
					outIndexesForB = append(outIndexesForB, 0) // Always same out channel
					DebugPrintf("[TEST in b] got %d\n", in)
					DebugPrintf("%v\n", bufferForB)
					return nil, nil, nil
				}),
				WithOnNoMoreData[int, int](func() ([]int, []int, error) {
					DebugPrintf("B->OnNoMoreData called!\n")
					return bufferForB, outIndexesForB, nil
				}),
			),
			NewSink[int](
				"c",
				WithSinkFunction(func(in int) error {
					gotValues = append(gotValues, in)
					return nil
				}),
			),
		),
	)
	require.NoError(t, err)

	// Resume all stages.
	tests.TestOrTimeout(t, tests.WithTimeout(time.Second), func(t tests.T) {
		p.Resume(ctx)
		err := p.Wait(ctx)
		require.NoError(t, err)
	})
	require.ElementsMatch(t, []int{1, 2, 3}, gotValues)
}

func TestWithSequentialOutputs(t *testing.T) {
	defer PrintAllDebugLines()
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	// Prepare test.
	gotValues := make([]int, 0)
	currentIndex := 0

	// Create pipeline.
	p, err := NewPipeline(
		func(p *Pipeline) {
			// 1->2->3->4
			//     \__/
			s1 := p.Stages[0].(*Source[int])
			s2 := p.Stages[1].(*Stage[int, int])
			s3 := p.Stages[2].(*Stage[int, int])
			s4 := p.Stages[3].(*Sink[int])

			LinkStagesFanOut(SourceAsStage(s1), s2)
			LinkStagesAt(s2, 0, s3, 0)
			LinkStagesAt(s2, 1, SinkAsStage(s4), 0)
			LinkStagesAt(s3, 0, SinkAsStage(s4), 1)
		},
		WithStages(
			NewSource[int](
				"1", // source.
				WithSourceFunction(func() ([]int, []int, error) {
					// As a source of data.
					inData := []int{1, 2, 3}
					DebugPrintf("[TEST] source index %d\n", currentIndex)
					if currentIndex >= len(inData) {
						return nil, nil, NoMoreData
					}
					defer func() { currentIndex++ }()
					return inData[currentIndex : currentIndex+1], []int{0}, nil
				}),
				WithSequentialOutputs[None, int](),
			),
			// Stage 2 has two output channels, to 3 and to 4.
			NewStage[int, int](
				"2", // adds 1.
				WithProcessFunction(func(in int) ([]int, []int, error) {
					return []int{in + 1, in + 1}, []int{0, 1}, nil
				}),
				WithMultiOutputChannels[int, int](2), // to 3 and 4
				WithSequentialOutputs[int, int](),
			),
			NewStage[int, int](
				"3", // multiply by 2.
				WithProcessFunction(func(in int) ([]int, []int, error) {
					return []int{in * 2}, []int{0}, nil
				}),
				WithSequentialOutputs[int, int](),
			),
			NewSink[int](
				"4", // sink.
				WithSinkFunction(func(in int) error {
					gotValues = append(gotValues, in)
					DebugPrintf("[TEST] got %d\n", in)
					return nil
				}),
				WithMultiInputChannels[int, None](2),
				WithSequentialOutputs[int, None](),
			),
		),
	)
	require.NoError(t, err)

	// Resume all stages. There is nobody reading the last channel, so the pipeline will stall.
	tests.TestOrTimeout(t, tests.WithTimeout(time.Second), func(t tests.T) {
		p.Resume(ctx)
		err := p.Wait(ctx)
		DebugPrintf("[TEST] error 1: %v\n", err)
		require.NoError(t, err)
	})
}

// TestWithSequentialIO checks that the processing is done in order, since all inputs and outputs
// are read sequentially and in order.
func TestWithSequentialIO(t *testing.T) {
	defer PrintAllDebugLines()
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	// Prepare test.
	gotValues := make([]int, 0)
	currentIndex := 0

	// Create pipeline.
	p, err := NewPipeline(
		func(p *Pipeline) {
			// 1 ->2 ->4
			//  \->3_/
			s1 := p.Stages[0].(*Source[int])
			s2 := p.Stages[1].(*Stage[int, int])
			s3 := p.Stages[2].(*Stage[int, int])
			s4 := p.Stages[3].(*Sink[int])

			LinkStagesAt(SourceAsStage(s1), 0, s2, 0)
			LinkStagesAt(SourceAsStage(s1), 1, s3, 0)
			LinkStagesAt(s2, 0, SinkAsStage(s4), 0)
			LinkStagesAt(s3, 0, SinkAsStage(s4), 1)
		},
		WithStages(
			NewSource[int](
				"1", // source.
				WithSourceFunction(func() ([]int, []int, error) {
					// As a source of data.
					inData := []int{1, 2, 3, 4}
					DebugPrintf("[TEST] source index %d\n", currentIndex)
					if currentIndex >= len(inData) {
						return nil, nil, NoMoreData
					}
					defer func() { currentIndex++ }()
					return inData[currentIndex : currentIndex+1], []int{currentIndex % 2}, nil
				}),
				WithSequentialOutputs[None, int](),
				WithMultiOutputChannels[None, int](2),
			),
			// Stage 2 has two output channels, to 3 and to 4.
			NewStage[int, int](
				"2", // adds 1.
				WithProcessFunction(func(in int) ([]int, []int, error) {
					time.Sleep(100 * time.Millisecond) // be slower than the other branch.
					return []int{in + 1}, []int{0}, nil
				}),
				WithSequentialOutputs[int, int](),
			),
			NewStage[int, int](
				"3", // multiply by 2.
				WithProcessFunction(func(in int) ([]int, []int, error) {
					return []int{in * 2}, []int{0}, nil
				}),
				WithSequentialOutputs[int, int](),
			),
			NewSink[int](
				"4", // sink.
				WithSinkFunction(func(in int) error {
					gotValues = append(gotValues, in)
					DebugPrintf("[TEST] got %d\n", in)
					return nil
				}),
				WithMultiInputChannels[int, None](2),
				WithSequentialInputs[int, None](),
			),
		),
	)
	require.NoError(t, err)

	// Resume all stages. There is nobody reading the last channel, so the pipeline will stall.
	tests.TestOrTimeout(t, tests.WithTimeout(time.Second), func(t tests.T) {
		p.Resume(ctx)
		err := p.Wait(ctx)
		DebugPrintf("[TEST] error 1: %v\n", err)
		require.NoError(t, err)
	})
	require.Equal(t, []int{2, 4, 4, 8}, gotValues)
}

// TestAutoResume checks that if one stage stops in the middle of the processing without errors,
// the pipeline can resume automatically.
func TestAutoResume(t *testing.T) {
	defer PrintAllDebugLines()
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	// Prepare test.
	sourceIndex := 0
	itemCountAtB := 0
	incomingAtBisClosed := false
	gotValues := []int{}

	// In this pipeline, the B stage will stop accepting values every 2 items.
	p, err := NewPipeline(
		func(p *Pipeline) {
			// A -> B -> C
			a := SourceStage[int](p)
			b := StageAtIndex[int, int](p, 1)
			c := SinkStage[int](p)

			LinkStagesFanOut(a, b)
			LinkStagesFanOut(b, c)
		},
		WithStages(
			NewSource[int](
				"a",
				WithSourceFunction(func() ([]int, []int, error) {
					defer func() { sourceIndex++ }()
					inData := []int{1, 2, 3, 4}
					if sourceIndex >= len(inData) {
						return nil, nil, NoMoreData
					}
					return inData[sourceIndex : sourceIndex+1], []int{0}, nil
				}),
			),
			NewStage[int, int](
				"b",
				WithProcessFunction(func(in int) ([]int, []int, error) {
					var err error
					itemCountAtB++
					if itemCountAtB%2 == 0 {
						err = NoMoreData
					}
					return []int{in + 1}, []int{0}, err
				}),
				WithOnNoMoreData[int, int](func() ([]int, []int, error) {
					incomingAtBisClosed = true
					return nil, nil, nil
				}),
			),
			NewSink[int](
				"c",
				WithSinkFunction(func(in int) error {
					gotValues = append(gotValues, in)
					return nil
				}),
			),
		),
		// Stage B can stop the pipeline, and it will auto resume.
		WithAutoResumeAtStage(
			1, // B
			func() bool {
				DebugPrintf("[TEST] should auto resume? %v\n", !incomingAtBisClosed)
				return !incomingAtBisClosed
			},
			func(p *Pipeline) {
				DebugPrintf("[TEST] Relinking B->C\n")
				// Relink B->C
				b := StageAtIndex[int, int](p, 1)
				c := SinkStage[int](p)
				LinkStagesFanOut(b, c)
			},
			2, // Affects C.
		),
	)
	require.NoError(t, err)

	tests.TestOrTimeout(t, tests.WithTimeout(time.Second), func(t tests.T) {
		p.Resume(ctx)
		err := p.Wait(ctx)
		require.NoError(t, err)
	})
	require.Equal(t, []int{2, 3, 4, 5}, gotValues)
}

func TestAutoResumeAtSource(t *testing.T) {
	defer PrintAllDebugLines()
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	// Prepare test.
	sourceIndex := 0
	sourceIsFinished := false
	gotValues := []int{}

	// In this pipeline, the B stage will stop accepting values every 2 items.
	linkFunc := func(p *Pipeline) {
		// A -> B -> D
		//  \__ C __/
		a := SourceStage[int](p)          // sends to either b or c, alternatively
		b := StageAtIndex[int, int](p, 1) // adds 10
		c := StageAtIndex[int, int](p, 2) // adds 20
		d := SinkStage[int](p)            // stores valkues

		LinkStagesAt(a, 0, b, 0)
		LinkStagesAt(a, 1, c, 0)

		LinkStagesAt(b, 0, d, 0)
		LinkStagesAt(c, 0, d, 1)
	}
	p, err := NewPipeline(
		linkFunc,
		WithStages(
			NewSource[int](
				"a",
				WithMultiOutputChannels[None, int](2),
				WithSequentialOutputs[None, int](),
				WithSourceFunction(func() ([]int, []int, error) {
					defer func() { sourceIndex++ }()
					inData := []int{1, 2, 3, 4, 5, 6, 7}
					if sourceIndex >= len(inData) {
						sourceIsFinished = true
						return nil, nil, NoMoreData
					}

					// There is data to send.
					var err error
					if (sourceIndex+1)%3 == 0 {
						// Bundle completed.
						err = NoMoreData
					}
					return inData[sourceIndex : sourceIndex+1], []int{sourceIndex % 2}, err
				}),
			),
			NewStage[int, int](
				"b",
				WithSequentialOutputs[int, int](),
				WithProcessFunction(func(in int) ([]int, []int, error) {
					return []int{in + 10}, []int{0}, nil
				}),
			),
			NewStage[int, int](
				"c",
				WithSequentialOutputs[int, int](),
				WithProcessFunction(func(in int) ([]int, []int, error) {
					return []int{in + 20}, []int{0}, nil
				}),
			),
			NewSink[int](
				"d",
				WithMultiInputChannels[int, None](2),
				WithSequentialInputs[int, None](),
				WithSinkFunction(func(in int) error {
					gotValues = append(gotValues, in)
					return nil
				}),
			),
		),
		// Source stage can stop the pipeline, and it will auto resume.
		WithAutoResumeAtStage(
			0, // A
			func() bool {
				DebugPrintf("[TEST] should auto resume? %v\n", !sourceIsFinished)
				return !sourceIsFinished
			},
			linkFunc,
			// Affects everybody else, i.e., B, C, and D.
			1, 2, 3,
		),
	)
	require.NoError(t, err)

	tests.TestOrTimeout(t, tests.WithTimeout(time.Second), func(t tests.T) {
		p.Resume(ctx)
		err := p.Wait(ctx)
		require.NoError(t, err)
	})
	// Each batch must be sorted by channel number at the sink, in a staggered way.
	// The sorting resets at each batch.
	// From the sorted output arriving at the link point of view:
	// Batch 1 looks like: [ch0]<-11, [ch1]<-22, [ch0]<-13
	// Batch 2 looks like: [ch0]<-15, [ch1]<-24, [ch1]<-26
	// Batch 3 looks like: [ch0]<-17
	batches := []int{}
	batches = append(batches, []int{11, 22, 13}...)
	batches = append(batches, []int{15, 24, 26}...)
	batches = append(batches, []int{17}...)
	require.Equal(t, batches, gotValues)
}

func TestAutoResumeAtSink(t *testing.T) {
	defer PrintAllDebugLines()
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	// Prepare test.
	sourceIndex := 0
	itemCountAtSink := 0
	incomingAtSinkIsClosed := false
	gotValues := []int{}

	// In this pipeline, the B stage will stop accepting values every 2 items.
	p, err := NewPipeline(
		func(p *Pipeline) {
			// A -> B -> D
			//  \__ C __/
			a := SourceStage[int](p)          // sends to either b or c, alternatively
			b := StageAtIndex[int, int](p, 1) // adds 10
			c := StageAtIndex[int, int](p, 2) // adds 20
			d := SinkStage[int](p)

			LinkStagesAt(a, 0, b, 0)
			LinkStagesAt(a, 1, c, 0)

			LinkStagesAt(b, 0, d, 0)
			LinkStagesAt(c, 0, d, 1)
		},
		WithStages(
			NewSource[int](
				"a",
				WithMultiOutputChannels[None, int](2),
				WithSequentialOutputs[None, int](),
				WithSourceFunction(func() ([]int, []int, error) {
					defer func() { sourceIndex++ }()
					inData := []int{1, 2, 3, 4, 5, 6, 7}
					if sourceIndex >= len(inData) {
						return nil, nil, NoMoreData
					}
					return inData[sourceIndex : sourceIndex+1], []int{sourceIndex % 2}, nil
				}),
			),
			NewStage[int, int](
				"b",
				WithSequentialOutputs[int, int](),
				WithProcessFunction(func(in int) ([]int, []int, error) {
					return []int{in + 10}, []int{0}, nil
				}),
			),
			NewStage[int, int](
				"c",
				WithSequentialOutputs[int, int](),
				WithProcessFunction(func(in int) ([]int, []int, error) {
					return []int{in + 20}, []int{0}, nil
				}),
			),
			NewSink[int](
				"d",
				WithMultiInputChannels[int, None](2),
				WithSequentialInputs[int, None](),
				WithSinkFunction(func(in int) error {
					gotValues = append(gotValues, in)
					var err error
					itemCountAtSink++
					if itemCountAtSink%3 == 0 {
						DebugPrintf("[TEST] [d] bundle reached: %v\n", gotValues)
						err = NoMoreData
					}
					return err
				}),
				WithOnNoMoreData[int, None](func() ([]None, []int, error) {
					DebugPrintf("[TEST] [d] no more data called\n")
					incomingAtSinkIsClosed = true
					return nil, nil, nil
				}),
			),
		),
		// Sink stage can stop the pipeline, and it will auto resume.
		WithAutoResumeAtStage(
			3, // D
			func() bool {
				DebugPrintf("[TEST] should auto resume? %v\n", !incomingAtSinkIsClosed)
				return !incomingAtSinkIsClosed
			},
			func(p *Pipeline) {
				DebugPrintf("[TEST] Relinking Sink\n")
			},
			// Affects no one.
		),
	)
	require.NoError(t, err)

	tests.TestOrTimeout(t, tests.WithTimeout(time.Second), func(t tests.T) {
		p.Resume(ctx)
		err := p.Wait(ctx)
		require.NoError(t, err)
	})
	require.Equal(t, []int{11, 22, 13, 24, 15, 26, 17}, gotValues)
}

func TestStallStages(t *testing.T) {
	defer PrintAllDebugLines()
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	// Prepare test.
	sentValues := atomic.Uint32{}
	gotValues := make([]int, 0)

	// Create pipeline.
	p, err := NewPipeline(
		func(p *Pipeline) {
			// 1 ->2 ->4
			//  \->3_/
			s1 := p.Stages[0].(*Source[int])
			s2 := p.Stages[1].(*Stage[int, int])
			s3 := p.Stages[2].(*Stage[int, int])
			s4 := p.Stages[3].(*Sink[int])

			LinkStagesAt(SourceAsStage(s1), 0, s2, 0)
			LinkStagesAt(SourceAsStage(s1), 1, s3, 0)
			LinkStagesAt(s2, 0, SinkAsStage(s4), 0)
			LinkStagesAt(s3, 0, SinkAsStage(s4), 1)
		},
		WithStages(
			NewSource[int](
				"1", // source.
				WithSourceSlice(&[]int{1, 2, 3, 4, 1, 2, 3, 4}, func(in int) (int, error) {
					defer sentValues.Add(1)
					return in % 2, nil
				}),
				WithMultiOutputChannels[None, int](2),
			),
			// Stage 2 has two output channels, to 3 and to 4.
			NewStage[int, int](
				"2", // adds 10.
				WithProcessFunction(func(in int) ([]int, []int, error) {
					time.Sleep(1 * time.Millisecond)
					return []int{in + 10}, []int{0}, nil
				}),
			),
			NewStage[int, int](
				"3", // adds 100.
				WithProcessFunction(func(in int) ([]int, []int, error) {
					time.Sleep(10 * time.Millisecond)
					return []int{in + 100}, []int{0}, nil
				}),
			),
			NewSink[int](
				"4", // sink.
				WithSinkFunction(func(in int) error {
					// Let's make the sink quite slow. This should check the workingStagesWg.
					time.Sleep(50 * time.Millisecond)
					gotValues = append(gotValues, in)
					return nil
				}),
				WithMultiInputChannels[int, None](2),
			),
		),
	)
	require.NoError(t, err)
	WithStallStages(
		p.StagesAt(1, 2, 3),
		func() {
			t.Logf("gotValues = %v", gotValues)
		},
		func(s StageLike) bool {
			time.Sleep(10 * time.Millisecond)
			t.Logf("stall evaluated at %s", s.Base().Name)
			return true
		},
		p.StagesAt(1, 2),
	)(p)

	// Resume all stages. There is nobody reading the last channel, so the pipeline will stall.
	tests.TestOrTimeout(t, tests.WithTimeout(time.Second), func(t tests.T) {
		p.Resume(ctx)
		err := p.Wait(ctx)
		DebugPrintf("[TEST] error 1: %v\n", err)
		require.NoError(t, err)
	})
	require.ElementsMatch(t, []int{101, 12, 103, 14, 101, 12, 103, 14}, gotValues)
}

// TestStallStagesConcurrency checks that the stages are still processed concurrently, also with
// the use of the WithStallStages option.
func TestStallStagesConcurrency(t *testing.T) {
	defer PrintAllDebugLines()
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	// Prepare test.
	sentValues := atomic.Uint32{}
	gotValues := make([]int, 0)
	alreadyChecked := atomic.Bool{}

	// Create pipeline.
	p, err := NewPipeline(
		func(p *Pipeline) {
			// 1 ->2 ->4
			//  \->3_/
			s1 := p.Stages[0].(*Source[int])
			s2 := p.Stages[1].(*Stage[int, int])
			s3 := p.Stages[2].(*Stage[int, int])
			s4 := p.Stages[3].(*Sink[int])

			LinkStagesAt(SourceAsStage(s1), 0, s2, 0)
			LinkStagesAt(SourceAsStage(s1), 1, s3, 0)
			LinkStagesAt(s2, 0, SinkAsStage(s4), 0)
			LinkStagesAt(s3, 0, SinkAsStage(s4), 1)
		},
		WithStages(
			NewSource[int](
				"1", // source.
				WithSourceSlice(&[]int{1, 2, 3, 4, 1, 2, 3, 4}, func(in int) (int, error) {
					defer sentValues.Add(1)
					return in % 2, nil
				}),
				WithMultiOutputChannels[None, int](2),
			),
			// Stage 2 has two output channels, to 3 and to 4.
			NewStage[int, int](
				"2", // adds 10.
				WithProcessFunction(func(in int) ([]int, []int, error) {
					for !alreadyChecked.Load() {
					}

					return []int{in + 10}, []int{0}, nil
				}),
			),
			NewStage[int, int](
				"3", // adds 100.
				WithProcessFunction(func(in int) ([]int, []int, error) {
					defer alreadyChecked.Store(true)
					return []int{in + 100}, []int{0}, nil
				}),
			),
			NewSink[int](
				"4", // sink.
				WithSinkFunction(func(in int) error {
					// Let's make the sink quite slow. This should check the workingStagesWg.
					gotValues = append(gotValues, in)
					return nil
				}),
				WithMultiInputChannels[int, None](2),
			),
		),
	)
	require.NoError(t, err)
	WithStallStages(
		p.StagesAt(0, 1, 2, 3),
		// Per bundle:
		func() {
			t.Logf("gotValues = %v", gotValues)
		},
		// Should stall?
		func(s StageLike) bool {
			stall := len(gotValues)%4 == 0
			t.Logf("stall evaluated at %s will return %v", s.Base().Name, stall)
			return stall
		},
		p.StagesAt(3),
	)(p)

	// Resume all stages. There is nobody reading the last channel, so the pipeline will stall.
	tests.TestOrTimeout(t, tests.WithTimeout(time.Second), func(t tests.T) {
		p.Resume(ctx)
		err := p.Wait(ctx)
		DebugPrintf("[TEST] error: %v\n", err)
		require.NoError(t, err)
	})
	require.ElementsMatch(t, []int{101, 12, 103, 14, 101, 12, 103, 14}, gotValues)
}

// TestStallEvaluationFunction checks that both the evaluation and the execution functions are not
// run with any other simultaneously. I.e. that the mutex contained in the WithStallStages actually
// works as expected.
func TestStallEvaluationFunction(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelF()

	// Simulation parameters.
	const N = 10_000
	const BundleSize = 100
	const ProcessingTimeAvg = 10 * time.Microsecond
	const ProcessingTimeStdDev = 10 * time.Microsecond

	// Needed for the pipeline.
	type Cert struct{}
	incomingData := make([]Cert, N)
	certCount := atomic.Uint64{}
	processFunctionRandomDuration := func() {
		nanos := random.RandomInt(
			t,
			int(ProcessingTimeAvg-ProcessingTimeStdDev),
			int(ProcessingTimeAvg+ProcessingTimeStdDev),
		)
		time.Sleep(time.Duration(nanos))
	}

	// First pipeline.
	//
	// a ┌-> b1 -┌-> c1 -┬-> d
	//   |-> b2  |-> c2 -|
	//  ...     ...     ...
	//   └-> bW -┴-> cW -┘
	//
	// All crisscross links, i.e. the data gets distributed to the first available next stage.

	const W = 16
	stages := make([]StageLike, 0)

	// State for the processing functions.
	processingAtA := atomic.Int32{}
	processingAtB := atomic.Int32{}
	processingAtC := atomic.Int32{}
	processingAtD := atomic.Int32{}

	a := NewSource(
		"source",
		WithSourceSlice(&incomingData, func(in Cert) (int, error) {
			processingAtA.Add(1)
			defer processingAtA.Add(-1)

			processFunctionRandomDuration()

			return 0, nil
		}),
	)
	stages = append(stages, a)

	b := make([]*Stage[Cert, Cert], W)
	for i := range b {
		b[i] = NewStage[Cert, Cert](
			fmt.Sprintf("b%02d", i),
			WithProcessFunction(func(in Cert) ([]Cert, []int, error) {
				processingAtB.Add(1)
				defer processingAtB.Add(-1)

				processFunctionRandomDuration()
				certCount.Add(1)

				return []Cert{in}, []int{0}, nil
			}),
		)
		stages = append(stages, b[i])
	}

	c := make([]*Stage[Cert, Cert], W)
	for i := range c {
		c[i] = NewStage[Cert, Cert](
			fmt.Sprintf("c%02d", i),
			WithProcessFunction(func(in Cert) ([]Cert, []int, error) {
				processingAtC.Add(1)
				defer processingAtC.Add(-1)

				processFunctionRandomDuration()

				return []Cert{in}, []int{0}, nil
			}),
		)
		stages = append(stages, c[i])
	}

	d := NewSink[Cert](
		"sink",
		WithSinkFunction(func(in Cert) error {
			processingAtD.Add(1)
			defer processingAtD.Add(-1)

			processFunctionRandomDuration()

			return nil
		}),
	)
	stages = append(stages, d)

	pipeline, err := NewPipeline(
		func(p *Pipeline) {
			// Link function.
			a := SourceAsStage(a)
			d := StagesAsSlice(SinkAsStage(d))

			LinkStagesDistribute(a, b...)
			LinkStagesCrissCross(b, c)
			LinkStagesCrissCross(c, d)
		},
		WithStages(stages...),
	)
	require.NoError(t, err)

	// Stalling.
	stallEvaluationInProgress := atomic.Bool{}
	stallExecutionInProgress := atomic.Bool{}

	checkNoProcessingAtTheMoment := func() {
		check := func(counter *atomic.Int32) {
			if c := counter.Load(); c != 0 {
				panic(fmt.Errorf("[TEST bundle function fail] concurrent processing is %d", c))
			}
			time.Sleep(10 * time.Microsecond)
		}

		check(&processingAtA)
		check(&processingAtB)
		check(&processingAtC)
		check(&processingAtD)
	}

	stall := WithStallStages(
		stages,
		func() {
			// Runs when stalled.
			DebugPrintf("running stall function\n")

			processFunctionRandomDuration()
			checkNoProcessingAtTheMoment()
			processFunctionRandomDuration()
			checkNoProcessingAtTheMoment()

			t.Logf("Bundle finished at %s", time.Now().Format(time.StampMicro))
			certCount.Store(0)
			stallExecutionInProgress.Store(false)
		},
		func(sl StageLike) bool {
			// Evaluate if should stall.
			if stallEvaluationInProgress.Swap(true) {
				panic("[TEST stall eval] concurrent call to evaluate function")
			}
			defer stallEvaluationInProgress.Store(false)

			willStall := certCount.Load() > BundleSize &&
				stallExecutionInProgress.CompareAndSwap(false, true)
			DebugPrintf("[%s] evaluating stall-> %v\n", sl.Base().Name, willStall)

			return willStall
		},
		stages[1+W:1+W+W], // "c" stages.
	)
	stall(pipeline) // Apply stall option.

	tests.TestOrTimeout(t, tests.WithContext(ctx), func(t tests.T) {
		pipeline.Resume(ctx)

		err = pipeline.Wait(ctx)
		require.NoError(t, err)
	})
}

func checkClosed[T any](t *testing.T, ch chan T) {
	_, ok := <-ch
	require.False(t, ok)
}

func checkAllClosed[T any](t *testing.T, chs []chan T) {
	for _, ch := range chs {
		checkClosed(t, ch)
	}
}
