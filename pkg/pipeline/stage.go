package pipeline

type StageLike interface {
	Prepare()
	Resume()
	StopAndWait() error
}

type Stage[IN, OUT any] struct {
	*Base // Common fields.
	// SinkBase[IN]    // It behaves (partially) as a sink, ingesting IN data.
	SourceBase[OUT] // It behaves (partially) as a source, spitting OUT data.

	IncomingCh chan IN // Incoming data channel to process.

	ProcessFunc func(in IN) (OUT, error) // From IN to OUT.
}

var _ StageLike = &Stage[int, string]{}

func NewStage[IN, OUT any](
	name string,
	options ...stageOption[IN, OUT],
) *Stage[IN, OUT] {

	base := NewBase(name)
	source := NewSourceBase[OUT](base)
	s := &Stage[IN, OUT]{
		Base:       base,
		SourceBase: *source,
	}
	for _, opt := range options {
		opt(s)
	}
	return s
}

type stageOption[IN, OUT any] func(*Stage[IN, OUT])

func WithProcessFunction[IN, OUT any](
	processFunc func(IN) (OUT, error),
) stageOption[IN, OUT] {
	return func(s *Stage[IN, OUT]) {
		s.ProcessFunc = processFunc
	}
}

func WithOutChannelSelector[IN, OUT any](
	outChSelector func(OUT) int,
) stageOption[IN, OUT] {
	return func(s *Stage[IN, OUT]) {
		s.OutChSelector = outChSelector
	}
}

func LinkStages[IN, OUT, LAST any](
	prev *Stage[IN, OUT],
	next *Stage[OUT, LAST],
) {
	prev.OutgoingCh = next.IncomingCh
	prev.NextErrCh = next.ErrCh
}

func (s *Stage[IN, OUT]) Prepare() {
	s.Base.Prepare()
	s.SourceBase.Prepare()
	s.IncomingCh = make(chan IN)

	s.SourceBase.GenerateFunc = s.generateFunc
}

// Resume resumes processing from this stage.
// This function creates new channels for the incoming data, error and stop channels.
func (s *Stage[IN, OUT]) Resume() {
	s.SourceBase.Resume()
	// Deleteme replace make chan with Source.Resume()
	// s.Source.Resume()
	// s.StopCh = make(chan none)

	// go s.processThisStage()
}

// StopAndWait stops this and following stages by closing this stage's outgoing channel.
// This stage's outgoing channel is the same as the next stage's incoming channel.
// This function waits for the next stage to finish and returns any error.
func (s *Stage[IN, OUT]) StopAndWait() error {
	// Stop listening on other goroutines from the next stage's error channel.
	// Also stop sending data to the outgoing channel. This means effectively, stop the
	// working resume goroutine. We explicitly indicate the goroutine to finish and
	// not to read any state from the next stage. We will do that here.
	s.Base.StopCh <- none{}

	return s.breakPipelineAndWait(nil)
}

func (s *Stage[IN, OUT]) breakPipelineAndWait(initialErr error) error {
	// // Indicate next stage to stop.
	// close(s.OutgoingCh())
	// // Read its status:
	// err := <-s.NextErrCh
	// // Coalesce with any error at this stage.
	// err = util.ErrorsCoalesce(initialErr, err)
	// // Propagate error backwards.
	// s.ErrCh <- err
	// // Close our own error channel.
	// close(s.ErrCh)
	// // Close the stop channel indicator.
	// close(s.StopCh)
	// return err

	return nil
}

func (s *Stage[IN, OUT]) generateFunc() (OUT, error) {
	var emptyOut OUT
	select {
	case in, ok := <-s.IncomingCh:
		if !ok {
			// Incoming channel was closed. No data to be written to outgoing channel.
			debugPrintf("[%s] no more data\n", s.Name)
			return emptyOut, NoMoreData
		}
		debugPrintf("[%s] incoming %v\n", s.Base.Name, in)
		return s.ProcessFunc(in)

	case <-s.StopCh:
		// We have been instructed to stop, without reading any other channel.
		return emptyOut, StopNoError

	case err := <-s.NextErrCh:
		debugPrintf("[%s] got error while reading incoming from next stage\n", s.Name)
		return emptyOut, err
	}
}

// func (s *Stage[IN, OUT]) processThisStage() {
// 	var foundError error
// readChannels:
// 	for {
// 		out, err := s.SourceBase.GenerateFunc()
// 		switch err {
// 		case NoMoreData:
// 			// Incoming channel was closed. No data to be written to the outgoing channel.
// 			debugPrintf("[%s] breaking processing\n", s.Name)
// 			break readChannels
// 		case StopNoError:
// 			// We have been instructed to stop, without reading any other channel.
// 			return
// 		case nil:
// 			// Data is ready to be sent.
// 			err := s.sendStopOrErrFromNext(out)
// 			switch err {
// 			case SentNoError:
// 				// Success writing to the outgoing channel, nothing else to do.
// 			case StopNoError:
// 				// We have been instructed to stop, without reading any other channel.
// 				return
// 			default:
// 				// We received an error from next stage while trying to write to it.
// 				foundError = err
// 				break readChannels
// 				// deleteme TODO: unify the stop and errFromNextStage cases
// 			}
// 		default:
// 			// We have received an error from the next stage while trying to read incoming.
// 			foundError = err
// 			break readChannels
// 		}
// 	}

// 	// Discard the coalesced error, as the function below propagates the error backwards already.
// 	s.breakPipelineAndWait(foundError)

// 	debugPrintf("[%s] done\n", s.Name)
// }

// func (s *Stage[IN, OUT]) processThisStage2() {
// 	var foundError error
// 	var out OUT
// readChannels:
// 	for {
// 		select {
// 		case data, ok := <-s.IncomingCh:
// 			fmt.Printf("incoming %v at %s\n", data, s.Name)
// 			if !ok {
// 				// Incoming channel was closed. No data to be written to outgoing channel.
// 				fmt.Printf("breaking processing at %s\n", s.Name)
// 				break readChannels
// 			}

// 			out, foundError = s.ProcessFunc(data)
// 			if foundError != nil {
// 				fmt.Printf("ORIGINAL error at %s\n", s.Name)
// 				break readChannels
// 			}

// 			foundError = s.sendStopOrErrFromNext(out)
// 			switch foundError {
// 			case SentNoError:
// 				// Success writing to the outgoing channel, nothing else to do.
// 			case StopNoError:
// 				// We have been instructed to stop, without reading any other channel.
// 				return
// 			default:
// 				// We received an error from next stage while trying to write to it.
// 				break readChannels
// 				// deleteme TODO: unify the stop and errFromNextStage cases
// 			}

// 			fmt.Printf("sent result %v at %s\n", out, s.Name)
// 			continue
// 		case foundError = <-s.nextErrCh:
// 			fmt.Printf("got error from next stage at %s\n", s.Name)
// 			break readChannels
// 		case <-s.stopCh:
// 			// We have been instructed to stop, without reading any other channel.
// 			return
// 		}
// 	}

// 	// Discard the coalesced error, as the function below propagates the error backwards already.
// 	s.breakPipelineAndWait(foundError)

// 	fmt.Printf("done at %s\n", s.Name)
// }
