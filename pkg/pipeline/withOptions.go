package pipeline

// WithProcessFunction allows the stage to create multiple outputs per given input.
// The outputs are sent to the next stage _with no order_.
func WithProcessFunction[IN, OUT any](
	processFunc func(IN) ([]OUT, []int, error),
) option[IN, OUT] {
	return newStageOption(
		func(s *Stage[IN, OUT]) {
			s.ProcessFunc = processFunc
		})
}

func WithMultiOutputChannels[IN, OUT any](
	numberOfChannels int,
) option[IN, OUT] {
	return newStageOption(func(s *Stage[IN, OUT]) {
		s.OutgoingChs = make([]chan OUT, numberOfChannels)
	})
}

func WithMultiInputChannels[IN, OUT any](
	numberOfChannels int,
) option[IN, OUT] {
	return newStageOption(func(s *Stage[IN, OUT]) {
		s.IncomingChs = make([]chan IN, numberOfChannels)
	})
}

// WithOnNoMoreData acts as WithProcessFunctionMultipleOutputs, but it is called without any input,
// when this stage has detected no more incoming data.
// The outputs are sent to the next stage _in no particular order_.
func WithOnNoMoreData[IN, OUT any](
	handler func() ([]OUT, []int, error),
) option[IN, OUT] {
	return newStageOption(func(s *Stage[IN, OUT]) {
		s.onNoMoreData = handler
	})
}

func WithOnErrorSending[IN, OUT any](
	handler func(err error, failedIndices []int),
) option[IN, OUT] {
	return newStageOption(func(s *Stage[IN, OUT]) {
		s.onErrorSending = handler
	})
}

// WithConcurrentInputs sets the input channels reading logic to spawn one goroutine per channel,
// allowing any incoming message to be passed to the stage, and not keeping any order.
// This is the default.
func WithConcurrentInputs[IN, OUT any]() option[IN, OUT] {
	return newStageOption(func(s *Stage[IN, OUT]) {
		s.buildAggregatedInput = s.readIncomingConcurrently
	})
}

// WithSequentialInputs changes the reading logic of the stage to always read its incoming channels
// in index order, starting with 0 and wrapping around len(s.IncomingChs).
// This means that if channel i-1 is blocked, the stage won't read channel i until that one is
// either unblocked, closed, or the stop signal for this stage is called.
func WithSequentialInputs[IN, OUT any]() option[IN, OUT] {
	return newStageOption(func(s *Stage[IN, OUT]) {
		s.buildAggregatedInput = s.readIncomingSequentially
	})
}

// WithCyclesAllowedSequentialOutputs sends the output on each output channel without allocating
// memory, and not blocking, at the expense of a higher CPU cost for this stage, as it continuously
// spins checking if the output channels are ready.
// This is the default.
func WithCyclesAllowedSequentialOutputs[IN, OUT any]() option[IN, OUT] {
	return newStageOption(func(s *Stage[IN, OUT]) {
		s.sendOutputs = s.sendOutputsCyclesAllowed
	})
}

// WithConcurrentOutputs changes the default sending logic to use a goroutine per output.
// This allows for an unordered, non-blocking delivery of the outputs to the next stages,
// at the expense of some allocations being made.
func WithConcurrentOutputs[IN, OUT any]() option[IN, OUT] {
	return newStageOption(func(s *Stage[IN, OUT]) {
		s.sendOutputs = s.sendOutputsConcurrent
	})
}

// WithSequentialOutputs changes the sending logic to the sequential propagation, which is the
// simplest one, but does not allow cycles in the stage connection graph.
// The sequential propagation is the cheapest method in terms of CPU consumption, but can reduce
// concurrency if few stages in a layer are receiving most of the data.
func WithSequentialOutputs[IN, OUT any]() option[IN, OUT] {
	return newStageOption(func(s *Stage[IN, OUT]) {
		s.sendOutputs = s.sendOutputsSequential
	})
}
