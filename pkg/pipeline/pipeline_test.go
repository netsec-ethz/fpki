package pipeline

import (
	"fmt"
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
				WithGeneratorFunction(func() (int, error) {
					// As a source of data.
					inData := []int{1, 2, 3}
					debugPrintf("[TEST] source index %d\n", currentIndex)
					if currentIndex >= len(inData) {
						return 0, NoMoreData
					}
					defer func() { currentIndex++ }()
					return inData[currentIndex], nil
				}),
			),
			NewStage[int, int](
				"b",
				WithProcessFunction(func(in int) (int, error) {
					// This b stage fails when it receives a 4.
					if in == 2 && firstTimeErrorAtB {
						firstTimeErrorAtB = false
						return 0, fmt.Errorf("error at stage b")
					}
					return in + 1, nil
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
	debugPrintf("[TEST] error 1: %s\n", err)
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
	checkClosed(t, a.OutgoingCh)
	checkClosed(t, b.OutgoingCh)
	checkClosed(t, c.OutgoingCh)
	checkClosed(t, a.NextErrCh)
	checkClosed(t, b.NextErrCh)
	checkClosed(t, c.NextErrCh)

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
	checkClosed(t, a.OutgoingCh)
	checkClosed(t, b.OutgoingCh)
	checkClosed(t, c.OutgoingCh)
	checkClosed(t, a.NextErrCh)
	checkClosed(t, b.NextErrCh)
	checkClosed(t, c.NextErrCh)
}

func checkClosed[T any](t *testing.T, ch chan T) {
	_, ok := <-ch
	require.False(t, ok)
}
