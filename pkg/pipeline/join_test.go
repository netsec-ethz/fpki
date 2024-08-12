package pipeline

import (
	"strconv"
	"testing"
	"time"

	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/stretchr/testify/require"
)

// TestJoinPipelines checks that joining two basic pipelines work.
func TestBasicJoinPipelines(t *testing.T) {
	defer PrintAllDebugLines()

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
				WithSourceFunction(func() ([]int, []int, error) {
					defer func() { p1SourceIndex++ }()
					inData := []int{1, 2, 3, 4, 5}
					if p1SourceIndex < len(inData) {
						debugPrintf("[a] [TEST] source function called with %v\n", inData[p1SourceIndex])
						return inData[p1SourceIndex : p1SourceIndex+1], []int{0}, nil
					}
					return nil, nil, NoMoreData
				}),
				WithSequentialOutputs[None, int](),
			),
			NewStage[int, string](
				"b",
				WithProcessFunction(func(in int) ([]string, []int, error) {
					s := strconv.Itoa(in)
					return []string{s}, []int{0}, nil
				}),
				WithSequentialOutputs[int, string](),
			),
			NewSink[string](
				"c",
				WithSinkFunction(func(in string) error {
					debugPrintf("[c] [TEST] sink function called with %v\n", in)
					p1SinkCallCount++
					return nil
				}),
				WithSequentialOutputs[string, None](),
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
				WithSourceChannel(p2SourceCh, func(in string) (int, error) {
					debugPrintf("[d] [TEST] source channel processing called with %v\n", in)
					p2SourceCallCount++
					return 0, nil
				}),
				WithSequentialOutputs[None, string](),
			),
			NewSink[string](
				"e",
				WithSinkFunction(func(in string) error {
					debugPrintf("[e] [TEST] sink function called with %v\n", in)
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
		jointPipeline.Resume()
		err := jointPipeline.Wait()
		require.NoError(t, err)
	})
	require.Equal(t, []string{"1", "2", "3", "4", "5"}, p2GotValues)
	require.Equal(t, len(p2GotValues), p1SinkCallCount)
	require.Equal(t, len(p2GotValues), p2SourceCallCount)
}
