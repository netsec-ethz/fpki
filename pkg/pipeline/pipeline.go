package pipeline

type Pipeline struct {
	LinkFunc func(p *Pipeline)
	Stages   []StageLike
}

func NewPipeline(
	linkFunc func(p *Pipeline),
	options ...pipelineOptions) *Pipeline {
	p := &Pipeline{
		LinkFunc: linkFunc,
	}
	for _, opt := range options {
		opt(p)
	}
	return p
}

type pipelineOptions func(*Pipeline)

func WithStages(stages ...StageLike) pipelineOptions {
	return func(p *Pipeline) {
		stages := stages
		p.Stages = make([]StageLike, len(stages))
		copy(p.Stages, stages)
	}
}

func StageAtIndex[IN, OUT any](p *Pipeline, index int) *Stage[IN, OUT] {
	return p.Stages[index].(*Stage[IN, OUT])
}

func (p *Pipeline) Resume() {
	p.LinkFunc(p)
	// Now resume in reverse order
	for i := len(p.Stages) - 1; i >= 0; i-- {
		p.Stages[i].Resume()
	}
}

func (p *Pipeline) Wait() error {
	return nil
}
