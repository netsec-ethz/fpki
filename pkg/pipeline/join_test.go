package pipeline

import (
	"strconv"
	"testing"
	"time"

	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/stretchr/testify/require"
)

// TestBasicJoinPipelines checks that joining two basic pipelines work.
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
			),
			NewStage[int, string](
				"b",
				WithProcessFunction(func(in int) ([]string, []int, error) {
					s := strconv.Itoa(in)
					return []string{s}, []int{0}, nil
				}),
			),
			NewSink[string](
				"c",
				WithSinkFunction(func(in string) error {
					debugPrintf("[c] [TEST] sink function called with %v\n", in)
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

// TestBasicJoinPipelines checks that joining two basic pipelines work.
func TestComplexJoinPipelines(t *testing.T) {
	defer PrintAllDebugLines()

	// The pipelines are:
	// p1: A1[int] --> B1 --> D1[string]
	//              \_ C1 _/

	// p2: A2[string] --> B2 --> D2[string]
	//                 \_ C2 _/

	// The stage p1.A1 has auto resume enabled, to enact a bundle-size like behavior.

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
				WithSourceFunction(func() ([]int, []int, error) {
					defer func() { p1SourceIndex++ }()
					// inData := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
					inData := []int{1, 2} // deleteme
					if p1SourceIndex < len(inData) {
						debugPrintf("[a] [TEST] source function called with %v\n",
							inData[p1SourceIndex])
						return inData[p1SourceIndex : p1SourceIndex+1],
							[]int{p1SourceIndex % 2},
							nil
					}
					return nil, nil, NoMoreData
				}),
				WithMultiOutputChannels[None, int](2),
				WithSequentialOutputs[None, int](),
			),
			NewStage[int, string](
				"b1",
				WithProcessFunction(func(in int) ([]string, []int, error) {
					s := strconv.Itoa(in)
					// deleteme uncomment below
					// time.Sleep(10 * time.Millisecond)
					return []string{s}, []int{0}, nil
				}),
				WithSequentialInputs[int, string](),
				WithSequentialOutputs[int, string](),
			),
			NewStage[int, string](
				"c1",
				WithProcessFunction(func(in int) ([]string, []int, error) {
					s := strconv.Itoa(in)
					return []string{s}, []int{0}, nil
				}),
				WithSequentialInputs[int, string](),
				WithSequentialOutputs[int, string](),
			),
			NewSink[string](
				"d1",
				WithSinkFunction(func(in string) error {
					debugPrintf("[d1] [TEST] sink function called with %v\n", in)
					p1SinkCallCount++
					if p1SinkCallCount%3 == 0 { // Bundle size reached.
						return NoMoreData
					}
					return nil
				}),
				// TODO: desirable to automate not calling autoresume when no input.
				// WithOnNoMoreData[string, None](func() ([]None, []int, error) {
				// 	p1SinkOnNoMoreDataCalled = true
				// 	return nil, nil, nil
				// }),
				WithMultiInputChannels[string, None](2),
				WithSequentialInputs[string, None](),
			),
		),
		// WithAutoResumeAtStage(
		// 	3, // sink
		// 	func() bool {
		// 		return !p1SinkOnNoMoreDataCalled
		// 	},
		// 	func(p *Pipeline) {
		// 		// relink function, nothing to relink.
		// 	},
		// 	// no stages affected.
		// ),
	)
	_ = p1SinkOnNoMoreDataCalled // deleteme
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
				WithSourceChannel(p2SourceCh, func(in string) (int, error) {
					defer func() { p2SourceCallCount++ }()
					return p2SourceCallCount % 2, nil
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
					debugPrintf("[d2] [TEST] sink function called with %v\n", in)
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
		jointPipeline.Resume()
		err := jointPipeline.Wait()
		require.NoError(t, err)
	})
	require.Equal(t, []int{1, 2}, p2GotValues)
	require.Equal(t, len(p2GotValues), p1SinkCallCount)
	require.Equal(t, len(p2GotValues), p2SourceCallCount)
}
