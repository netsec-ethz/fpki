package pipeline_test

import (
	"testing"
	"time"

	"github.com/netsec-ethz/fpki/pkg/pipeline"
	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/stretchr/testify/require"
)

func TestMemAllocationOverhead(t *testing.T) {
	stage := pipeline.NewStage[int, int](
		"worker",
		pipeline.WithProcessFunctionMultipleOutputs(func(int) ([]int, []int, error) {
			return nil, nil, nil
		}),
	)
	stage.Prepare()

	// Mock a sink.
	sinkErrCh := make(chan error)
	stage.NextErrChs[0] = sinkErrCh
	go func() {
		for range stage.OutgoingChs[0] {
		}
		close(sinkErrCh)
	}()

	// Resume stage. It will stall until input from the source is given.
	stage.Resume()

	// Mock a source.
	N := 100
	source := func() {
		for i := 0; i < N; i++ {
			stage.IncomingChs[0] <- i
		}
		close(stage.IncomingChs[0])
	}

	// We are interested in measuring the processing regime of the stage, thus we are
	// taking a long nap to let the stage resume steps finish.
	time.Sleep(time.Second)

	var err error
	allocs := tests.AllocsPerRun(func() {
		go source()
		err = <-stage.ErrorChannel()
	})
	require.NoError(t, err)
	require.Equal(t, 0, allocs)
}
