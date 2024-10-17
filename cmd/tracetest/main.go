package main

import (
	"context"
	"fmt"
	"os"
	"time"

	pip "github.com/netsec-ethz/fpki/pkg/pipeline"
)

func main() {
	os.Exit(mainFunc())
}

func mainFunc() int {
	fmt.Println("hello world")

	ctx, cancelF := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelF()

	values := make([]int, 22)
	for i := range values {
		values[i] = i
	}
	const bufferSize = 10
	buffer := make([]int, 0, bufferSize)

	pipeline, err := pip.NewPipeline(
		func(p *pip.Pipeline) {
			// link function
			s1 := pip.SourceStage[int](p)
			s2 := pip.StageAtIndex[int, int](p, 1)
			s3 := pip.StageAtIndex[int, int](p, 2)
			s4 := pip.SinkStage[int](p)
			pip.LinkStagesFanOut(s1, s2)
			pip.LinkStagesFanOut(s2, s3)
			pip.LinkStagesFanOut(s3, s4)
		},
		pip.WithStages(
			pip.NewSource[int](
				"source",
				pip.WithSourceSlice(&values, func(in int) (int, error) {
					return 0, nil
				}),
			),
			pip.NewStage[int, int](
				"add-one",
				pip.WithProcessFunction(func(in int) ([]int, []int, error) {
					return []int{in + 1}, []int{0}, nil
				}),
			),
			pip.NewStage[int, int](
				"buffered-output",
				pip.WithProcessFunction(func(in int) ([]int, []int, error) {
					buffer = append(buffer, in)
					if len(buffer) == bufferSize {
						// send to sink
						newBuffer := make([]int, bufferSize)
						copy(newBuffer, buffer)
						buffer = buffer[:0] // reuse buffer
						outChannels := make([]int, bufferSize)
						return newBuffer, outChannels, nil
					}
					return nil, nil, nil
				}),
				pip.WithOnNoMoreData[int, int](func() ([]int, []int, error) {
					outChannels := make([]int, len(buffer))
					return buffer, outChannels, nil
				}),
			),
			pip.NewSink[int](
				"sink",
				pip.WithSinkFunction(func(in int) error {
					fmt.Printf("%d ", in)
					return nil
				}),
			),
		),
	)
	checkErr(err)

	pipeline.Resume(ctx)
	err = pipeline.Wait(ctx)
	fmt.Println()
	checkErr(err)
	fmt.Println("done.")

	return 0
}

func checkErr(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
