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
					inData := []int{1, 2, 3, 4, 5}
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
					if in == 4 && firstTimeErrorAtB {
						firstTimeErrorAtB = false
						return 0, fmt.Errorf("error at stage b")
					}
					return in + 2, nil
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
	currentIndex -= 2 // Because of the error at b, and a failing to send the next item.

	// We can now resume.
	debugPrintf("------------------------ RESUMING ----------------------\n")
	p.Resume()
	err = p.Wait()
	require.NoError(t, err)
	require.Equal(t, []int{3, 4, 5, 6, 7}, gotValues)
}

func checkClosed[T any](t *testing.T, ch chan T) {
	_, ok := <-ch
	require.False(t, ok)
}
