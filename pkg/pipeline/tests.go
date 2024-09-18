package pipeline

import "github.com/netsec-ethz/fpki/pkg/tests"

type DebugPurposesOnlyOutputType int

const (
	OutputSequential DebugPurposesOnlyOutputType = iota
	OutputSequentialCyclesAllowed
	OutputConcurrent
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
		WithSequentialOutputs[IN, OUT]().stage(s)
	case OutputSequentialCyclesAllowed:
		WithCyclesAllowedSequentialOutputs[IN, OUT]().stage(s)
	case OutputConcurrent:
		WithConcurrentOutputs[IN, OUT]().stage(s)
	default:
		panic("DEBUG ONLY FUNCTION DebugOnlyPurposeSetOutputFunction BAD type")
	}
}
