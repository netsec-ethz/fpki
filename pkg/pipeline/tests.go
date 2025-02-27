package pipeline

import "github.com/netsec-ethz/fpki/pkg/tests"

type DebugPurposesOnlyOutputType int

const (
	OutputSequential DebugPurposesOnlyOutputType = iota
	OutputSequentialCyclesAllowed
	OutputConcurrent
	InputSequential
)

func TestOnlyPurposeSetOutputFunction[IN, OUT any](
	t tests.T,
	s *Stage[IN, OUT],
	outType DebugPurposesOnlyOutputType,
) {
	t.Logf("DEBUG ONLY FUNCTION DebugOnlyPurposeSetOutputFunction")
	if !tests.InsideTest() {
		panic("DEBUG ONLY FUNCTION DebugOnlyPurposeSetOutputFunction called outside test")
	}
	switch outType {
	case OutputSequential:
		WithSequentialOutputs[IN, OUT]().ApplyToStage(s)
	case OutputSequentialCyclesAllowed:
		WithCyclesAllowedSequentialOutputs[IN, OUT]().ApplyToStage(s)
	case OutputConcurrent:
		WithConcurrentOutputs[IN, OUT]().ApplyToStage(s)
	case InputSequential:
		WithSequentialInputs[IN, OUT]().ApplyToStage(s)
	default:
		panic("DEBUG ONLY FUNCTION DebugOnlyPurposeSetOutputFunction BAD type")
	}
}
