package pipeline_test

import (
	"context"
	"testing"
	"time"

	"github.com/netsec-ethz/fpki/pkg/pipeline"
	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/stretchr/testify/require"
)

func TestMemAllocationOverhead(t *testing.T) {
	defer pipeline.PrintAllDebugLines()
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	outs := []int{1}
	outChs := []int{0}

	stage := pipeline.NewStage[int, int](
		"worker",
		pipeline.WithProcessFunction(func(in int) ([]int, []int, error) {
			outs[0] = in + 1
			return outs, outChs, nil
		}),
		pipeline.WithSequentialInputs[int, int](),
		pipeline.WithSequentialOutputs[int, int](),
	)
	stage.Prepare(ctx)

	// Mock a sink.
	sinkErrCh := make(chan error)
	stage.NextErrChs[0] = sinkErrCh
	stage.OutgoingChs[0] = make(chan int)
	go func() {
		for range stage.OutgoingChs[0] {
		}
		close(sinkErrCh)
	}()

	// Resume stage. It will stall until input from the source is given.
	stage.Resume(ctx)

	// Mock a source.
	N := 1000
	startSourceCh := make(chan struct{})
	go func() {
		<-startSourceCh
		for i := 0; i < N; i++ {
			stage.IncomingChs[0] <- i
		}
		close(stage.IncomingChs[0])
	}()

	// We are interested in measuring the processing regime of the stage, thus we are
	// taking a long nap to let the stage resume steps finish.
	time.Sleep(100 * time.Millisecond)

	var err error
	allocs := tests.AllocsPerRun(func() {
		startSourceCh <- struct{}{}
		err = <-stage.Base().ErrCh
	})
	require.NoError(t, err)
	// The test is flaky: sometimes we get 0 allocations, sometimes 1.
	require.LessOrEqual(t, allocs, 1)
}
