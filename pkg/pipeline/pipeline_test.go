package pipeline

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/stretchr/testify/require"
)

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
				WithGeneratorFunction(func() (int, int, error) {
					// As a source of data.
					inData := []int{1, 2, 3}
					debugPrintf("[TEST] source index %d\n", currentIndex)
					if currentIndex >= len(inData) {
						return 0, 0, NoMoreData
					}
					defer func() { currentIndex++ }()
					return inData[currentIndex], 0, nil
				}),
			),
			NewStage[int, int](
				"b",
				WithProcessFunction(func(in int) (int, int, error) {
					// This b stage fails when it receives a 4.
					if in == 2 && firstTimeErrorAtB {
						firstTimeErrorAtB = false
						debugPrintf("[TEST] emitting ERROR ([b] stage)\n")
						return 0, 0, fmt.Errorf("error at stage b")
					}
					return in + 1, 0, nil
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
				WithGeneratorFunction(func() (int, int, error) {
					// As a source of data.
					return 1, 0, nil
				}),
			),
			NewStage[int, int](
				"b",
				WithProcessFunction(func(in int) (int, int, error) {
					defer func() { processedAtBcount++ }()
					if processedAtBcount == 10 {
						stopB.Done()
					}
					return in + 1, 0, nil
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
	gotValues := make([]int, 0)
	bundleSize := 4
	processedAtBcount := 0

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
				WithGeneratorFunction(func() (int, int, error) {
					// As a source of data.
					return 1, 0, nil
				}),
			),
			NewStage[int, int](
				"b",
				WithProcessFunction(func(in int) (int, int, error) {
					defer func() { processedAtBcount++ }()
					if processedAtBcount == bundleSize {
						return 0, 0, NoMoreData
					}
					return in + 1, 0, nil
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
	require.Equal(t, len(gotValues), bundleSize)
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
			//     ╲⎯⎯╱
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
				WithGeneratorFunction(func() (int, int, error) {
					// As a source of data.
					inData := []int{1, 2, 3}
					debugPrintf("[TEST] source index %d\n", currentIndex)
					if currentIndex >= len(inData) {
						return 0, 0, NoMoreData
					}
					defer func() { currentIndex++ }()
					return inData[currentIndex], 0, nil
				}),
			),
			// Stage 2 has two output channels, to 3 and to 4.
			NewStage[int, int](
				"2", // adds 1.
				WithProcessFunctionMultipleOutputs(func(in int) ([]int, []int, error) {
					return []int{in + 1, in + 1}, []int{0, 1}, nil
				}),
				WithMultiOutputChannels[int, int](2), // to 3 and 4
			),
			NewStage[int, int](
				"3", // multiply by 2.
				WithProcessFunction(func(in int) (int, int, error) {
					return in * 2, 0, nil
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
				WithGeneratorFunction(func() (int, int, error) {
					// As a source of data.
					inData := []int{1, 2, 3}
					debugPrintf("[TEST] source index %d\n", currentIndex)
					if currentIndex >= len(inData) {
						return 0, 0, NoMoreData
					}
					defer func() { currentIndex++ }()
					return inData[currentIndex], 0, nil
				}),
			),
			NewStage[int, int](
				"b",
				WithProcessFunctionMultipleOutputs(func(in int) ([]int, []int, error) {
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
				WithGeneratorFunction(func() (int, int, error) {
					// As a source of data.
					inData := []int{1, 2, 3}
					debugPrintf("[TEST] source index %d\n", currentIndex)
					if currentIndex >= len(inData) {
						return 0, 0, NoMoreData
					}
					defer func() { currentIndex++ }()
					return inData[currentIndex], 0, nil
				}),
			),
			NewStage[int, int](
				"b",
				WithProcessFunctionMultipleOutputs(func(in int) ([]int, []int, error) {
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
			//     ╲⎯⎯╱
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
				WithGeneratorFunction(func() (int, int, error) {
					// As a source of data.
					inData := []int{1, 2, 3}
					debugPrintf("[TEST] source index %d\n", currentIndex)
					if currentIndex >= len(inData) {
						return 0, 0, NoMoreData
					}
					defer func() { currentIndex++ }()
					return inData[currentIndex], 0, nil
				}),
			),
			// Stage 2 has two output channels, to 3 and to 4.
			NewStage[int, int](
				"2", // adds 1.
				WithProcessFunctionMultipleOutputs(func(in int) ([]int, []int, error) {
					return []int{in + 1, in + 1}, []int{0, 1}, nil
				}),
				WithMultiOutputChannels[int, int](2), // to 3 and 4
			),
			NewStage[int, int](
				"3", // multiply by 2.
				WithProcessFunction(func(in int) (int, int, error) {
					return in * 2, 0, nil
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

func checkClosed[T any](t *testing.T, ch chan T) {
	_, ok := <-ch
	require.False(t, ok)
}

func checkAllClosed[T any](t *testing.T, chs []chan T) {
	for _, ch := range chs {
		checkClosed(t, ch)
	}
}
