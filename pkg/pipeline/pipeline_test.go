package pipeline

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/stretchr/testify/require"
)

func TestSimple(t *testing.T) {
	defer PrintAllDebugLines()
	// Prepare test.
	sourceIndex := 0
	gotValues := []int{}

	p := NewPipeline(
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
					return []int{in + 1}, []int{0}, nil
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

	tests.TestOrTimeout(t, tests.WithTimeout(time.Second), func(t tests.T) {
		p.Resume()
		err := p.Wait()
		require.NoError(t, err)
	})
	require.Equal(t, []int{2, 3, 4, 5}, gotValues)
}

func TestPipeline(t *testing.T) {
	defer PrintAllDebugLines()
	// Prepare test.
	gotValues := make([]int, 0)
	currentIndex := 0
	firstTimeErrorAtB := true

	// Create pipeline.
	p := NewPipeline(
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
					debugPrintf("[TEST] source index %d\n", currentIndex)
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
					// This b stage fails when it receives a 4.
					if in == 2 && firstTimeErrorAtB {
						firstTimeErrorAtB = false
						debugPrintf("[TEST] emitting ERROR ([b] stage)\n")
						return nil, nil, fmt.Errorf("error at stage b")
					}
					return []int{in + 1}, []int{0}, nil
				}),
			),
			NewSink[int](
				"c",
				WithSinkFunction(func(in int) error {
					gotValues = append(gotValues, in)
					debugPrintf("[TEST] got %d\n", in)
					return nil
				}),
			),
		),
	)

	// Resume all stages. There is nobody reading the last channel, so the pipeline will stall.
	tests.TestOrTimeout(t, tests.WithTimeout(time.Second), func(t tests.T) {
		p.Resume()
		err := p.Wait()
		debugPrintf("[TEST] error 1: %v\n", err)
		require.Error(t, err)
	})

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

	currentIndex = len(gotValues) // Because of the errors, recover.

	// We can now resume.
	debugPrintf("------------------------ RESUMING ----------------------\n")
	tests.TestOrTimeout(t, tests.WithTimeout(time.Second), func(t tests.T) {
		p.Resume()
		err := p.Wait()
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

func TestStop(t *testing.T) {
	defer PrintAllDebugLines()
	// Prepare test.
	gotValues := make([]int, 0)
	processedAtBcount := 0
	stopB := sync.WaitGroup{}
	stopB.Add(1) // The test waits until b tells it to stop the pipeline.

	// Create pipeline.
	p := NewPipeline(
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
					return []int{1}, []int{0}, nil
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
					debugPrintf("[TEST] got %d\n", in)
					gotValues = append(gotValues, in)
					return nil
				}),
			),
		),
	)

	// Resume all stages. There is nobody reading the last channel, so the pipeline will stall.
	p.Resume()
	// Wait to stop the pipeline in the middle of the process.
	stopB.Wait()
	err := StageAtIndex[int, int](p, 1).StopAndWait()
	require.NoError(t, err)
	require.LessOrEqual(t, 10, len(gotValues))
}

func TestBundleSize(t *testing.T) {
	defer PrintAllDebugLines()
	// Prepare test.
	sourceValue := 0
	bundleSize := 4
	processedAtBcount := 0
	gotValues := make([]int, 0)

	// Create pipeline.
	p := NewPipeline(
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
					defer func() { sourceValue++ }()
					return []int{sourceValue}, []int{0}, nil
				}),
			),
			NewStage[int, int](
				"b",
				WithProcessFunction(func(in int) ([]int, []int, error) {
					defer func() { processedAtBcount++ }()
					var err error
					if (processedAtBcount+1)%bundleSize == 0 {
						err = NoMoreData
					}
					return []int{in + 1}, []int{0}, err
				}),
			),
			NewSink[int](
				"c",
				WithSinkFunction(func(in int) error {
					debugPrintf("[TEST] got %d\n", in)
					gotValues = append(gotValues, in)
					return nil
				}),
			),
		),
	)

	// Resume all stages. There is nobody reading the last channel, so the pipeline will stall.
	p.Resume()
	// Wait to stop the pipeline in the middle of the process.
	err := p.Wait()
	require.NoError(t, err)
	require.Equal(t, bundleSize, len(gotValues))
	// Check that the values were inserted in the correct order.
	require.Equal(t, []int{1, 2, 3, 4}, gotValues)

	// Continue processing one more bundle.
	p.Resume()
	err = p.Wait()
	require.NoError(t, err)
	require.Equal(t, 2*bundleSize, len(gotValues))
	// require.Equal(t, []int{1, 2, 3, 4, 5, 6, 7, 8}, gotValues)
}

func TestMultiChannel(t *testing.T) {
	defer PrintAllDebugLines()
	// Prepare test.
	gotValues := make([]int, 0)
	currentIndex := 0

	// Create pipeline.
	p := NewPipeline(
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
					debugPrintf("[TEST] source index %d\n", currentIndex)
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
					debugPrintf("[TEST] got %d\n", in)
					return nil
				}),
				WithMultiInputChannels[int, None](2),
			),
		),
	)

	// Resume all stages. There is nobody reading the last channel, so the pipeline will stall.
	p.Resume()
	err := p.Wait()
	debugPrintf("[TEST] error 1: %v\n", err)
	require.NoError(t, err)
}

func TestMultipleOutputs(t *testing.T) {
	defer PrintAllDebugLines()
	// Prepare test.
	gotValues := make([]int, 0)
	currentIndex := 0

	// Create pipeline.
	p := NewPipeline(
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
					debugPrintf("[TEST] source index %d\n", currentIndex)
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
					debugPrintf("[TEST] got %d\n", in)
					gotValues = append(gotValues, in)
					return nil
				}),
			),
		),
	)

	// Resume all stages. There is nobody reading the last channel, so the pipeline will stall.
	p.Resume()
	// Wait to stop the pipeline in the middle of the process.
	err := p.Wait()
	require.NoError(t, err)
	require.ElementsMatch(t, []int{1, 2, 2, 3, 3, 4}, gotValues)
}

func TestOnNoMoreData(t *testing.T) {
	defer PrintAllDebugLines()
	// Prepare test.
	gotValues := make([]int, 0)
	currentIndex := 0
	bufferForB := make([]int, 0, 2048)
	outIndexesForB := make([]int, 0, len(bufferForB))

	// Create pipeline.
	p := NewPipeline(
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
					debugPrintf("[TEST] source index %d\n", currentIndex)
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
					debugPrintf("[TEST in b] got %d\n", in)
					debugPrintf("%v\n", bufferForB)
					return nil, nil, nil
				}),
				WithOnNoMoreData[int, int](func() ([]int, []int, error) {
					debugPrintf("B->OnNoMoreData called!\n")
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

	// Resume all stages.
	p.Resume()
	err := p.Wait()
	require.NoError(t, err)
	require.ElementsMatch(t, []int{1, 2, 3}, gotValues)
}

func TestWithSequentialOutputs(t *testing.T) {
	defer PrintAllDebugLines()
	// Prepare test.
	gotValues := make([]int, 0)
	currentIndex := 0

	// Create pipeline.
	p := NewPipeline(
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
					debugPrintf("[TEST] source index %d\n", currentIndex)
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
					debugPrintf("[TEST] got %d\n", in)
					return nil
				}),
				WithMultiInputChannels[int, None](2),
				WithSequentialOutputs[int, None](),
			),
		),
	)

	// Resume all stages. There is nobody reading the last channel, so the pipeline will stall.
	p.Resume()
	err := p.Wait()
	debugPrintf("[TEST] error 1: %v\n", err)
	require.NoError(t, err)
}

// TestWithSequentialIO checks that the processing is done in order, since all inputs and outputs
// are read sequentially and in order.
func TestWithSequentialIO(t *testing.T) {
	defer PrintAllDebugLines()
	// Prepare test.
	gotValues := make([]int, 0)
	currentIndex := 0

	// Create pipeline.
	p := NewPipeline(
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
					debugPrintf("[TEST] source index %d\n", currentIndex)
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
					debugPrintf("[TEST] got %d\n", in)
					return nil
				}),
				WithMultiInputChannels[int, None](2),
				WithSequentialInputs[int, None](),
			),
		),
	)

	// Resume all stages. There is nobody reading the last channel, so the pipeline will stall.
	tests.TestOrTimeout(t, tests.WithTimeout(time.Second), func(t tests.T) {
		p.Resume()
		err := p.Wait()
		debugPrintf("[TEST] error 1: %v\n", err)
		require.NoError(t, err)
	})
	require.Equal(t, []int{2, 4, 4, 8}, gotValues)
}

// TestAutoResume checks that if one stage stops in the middle of the processing without errors,
// the pipeline can resume automatically.
func TestAutoResume(t *testing.T) {
	defer PrintAllDebugLines()
	// Prepare test.
	sourceIndex := 0
	itemCountAtB := 0
	incomingAtBisClosed := false
	gotValues := []int{}

	// In this pipeline, the B stage will stop accepting values every 2 items.
	p := NewPipeline(
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
				debugPrintf("[TEST] should auto resume? %v\n", !incomingAtBisClosed)
				return !incomingAtBisClosed
			},
			func(p *Pipeline) {
				debugPrintf("[TEST] Relinking B->C\n")
				// Relink B->C
				b := StageAtIndex[int, int](p, 1)
				c := SinkStage[int](p)
				LinkStagesFanOut(b, c)
			},
			2, // Affects C.
		),
	)

	// tests.TestOrTimeout(t, tests.WithTimeout(time.Second), func(t tests.T) {
	tests.TestOrTimeout(t, tests.WithTimeout(time.Hour), func(t tests.T) { // deleteme
		p.Resume()
		err := p.Wait()
		require.NoError(t, err)
	})
	require.Equal(t, []int{2, 3, 4, 5}, gotValues)
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
