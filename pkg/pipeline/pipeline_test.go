package pipeline

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPipeline(t *testing.T) {
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

			LinkStages(SourceAsStage(a), b)
			LinkStages(b, SinkAsStage(c))
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
						debugPrintf("[TEST] emitting error ([b] stage)\n")
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
	p.Resume()
	err := p.Wait()
	debugPrintf("[TEST] error 1: %v\n", err)
	require.Error(t, err)

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
	checkClosed(t, a.IncomingCh)
	checkClosed(t, b.IncomingCh)
	checkClosed(t, c.IncomingCh)
	checkAllClosed(t, a.OutgoingChs)
	checkAllClosed(t, b.OutgoingChs)
	checkAllClosed(t, c.OutgoingChs)
	checkAllClosed(t, a.NextErrChs)
	checkAllClosed(t, b.NextErrChs)
	checkAllClosed(t, c.NextErrChs)

	currentIndex = len(gotValues) // Because of the errors, recover.

	// We can now resume.
	debugPrintf("------------------------ RESUMING ----------------------\n")
	p.Resume()
	err = p.Wait()
	require.NoError(t, err)
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
	checkClosed(t, a.IncomingCh)
	checkClosed(t, b.IncomingCh)
	checkClosed(t, c.IncomingCh)
	checkAllClosed(t, a.OutgoingChs)
	checkAllClosed(t, b.OutgoingChs)
	checkAllClosed(t, c.OutgoingChs)
	checkAllClosed(t, a.NextErrChs)
	checkAllClosed(t, b.NextErrChs)
	checkAllClosed(t, c.NextErrChs)
}

func TestStop(t *testing.T) {
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

			LinkStages(SourceAsStage(a), b)
			LinkStages(b, SinkAsStage(c))
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
	err := p.Stages[1].StopAndWait()
	require.NoError(t, err)
	require.LessOrEqual(t, 10, len(gotValues))
}

func TestBundleSize(t *testing.T) {
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

			LinkStages(SourceAsStage(a), b)
			LinkStages(b, SinkAsStage(c))
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

func checkClosed[T any](t *testing.T, ch chan T) {
	_, ok := <-ch
	require.False(t, ok)
}

func checkAllClosed[T any](t *testing.T, chs []chan T) {
	for _, ch := range chs {
		checkClosed(t, ch)
	}
}
