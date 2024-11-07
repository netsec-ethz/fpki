package pipeline

type option[IN, OUT any] interface {
	ApplyToStage(*Stage[IN, OUT])
	ApplyToSource(*Source[OUT])
	ApplyToSink(*Sink[IN])
}

type baseOption[IN, OUT any] struct{}

func (baseOption[IN, OUT]) ApplyToStage(*Stage[IN, OUT]) {}
func (baseOption[IN, OUT]) ApplyToSource(*Source[OUT])   {}
func (baseOption[IN, OUT]) ApplyToSink(*Sink[IN])        {}

var _ option[int, string] = stageOption[int, string]{}
var _ option[None, int] = sourceOption[int]{}
var _ option[string, None] = sinkOption[string]{}

func newStageOption[IN, OUT any](opt func(*Stage[IN, OUT])) option[IN, OUT] {
	return stageOption[IN, OUT]{option: opt}
}

func newSourceOption[OUT any](opt func(*Source[OUT])) option[None, OUT] {
	return sourceOption[OUT]{option: opt}
}

func newSinkOption[IN any](opt func(*Sink[IN])) option[IN, None] {
	return sinkOption[IN]{option: opt}
}

type stageOption[IN, OUT any] struct {
	baseOption[IN, OUT]
	option func(*Stage[IN, OUT])
}

type sourceOption[OUT any] struct {
	baseOption[None, OUT]
	option func(*Source[OUT])
}

type sinkOption[IN any] struct {
	baseOption[IN, None]
	option func(*Sink[IN])
}

func (o stageOption[IN, OUT]) ApplyToStage(s *Stage[IN, OUT]) {
	o.option(s)
}

func (o sourceOption[OUT]) ApplyToSource(s *Source[OUT]) {
	o.option(s)
}

func (o sinkOption[IN]) ApplyToSink(s *Sink[IN]) {
	o.option(s)
}
