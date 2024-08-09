package pipeline

type option[IN, OUT any] interface {
	stage(*Stage[IN, OUT])
	source(*Source[OUT])
	sink(*Sink[IN])
}

type baseOption[IN, OUT any] struct{}

func (baseOption[IN, OUT]) stage(*Stage[IN, OUT]) {}
func (baseOption[IN, OUT]) source(*Source[OUT])   {}
func (baseOption[IN, OUT]) sink(*Sink[IN])        {}

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

func (o stageOption[IN, OUT]) stage(s *Stage[IN, OUT]) {
	o.option(s)
}

func (o sourceOption[OUT]) source(s *Source[OUT]) {
	o.option(s)
}

func (o sinkOption[IN]) sink(s *Sink[IN]) {
	o.option(s)
}
