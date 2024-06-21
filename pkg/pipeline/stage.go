package pipeline

import (
	"fmt"

	"github.com/netsec-ethz/fpki/pkg/util"
)

type StageLike interface {
	Resume()
	StopAndWait() error
}

type Stage[IN, OUT any] struct {
	Name       string
	IncomingCh *chan IN  // Incoming data channel to process.
	OutgoingCh *chan OUT // Data processed goes here.

	ErrCh     *chan error // To be read by the previous stage.
	NextErrCh *chan error // Next stage's error channel.
	StopCh    chan none   // Indicates this stage to stop.

	ProcessFunc   func(in IN) (OUT, error) // From IN to OUT.
	OutChSelector func(data OUT) int       // Selects which outgoing channel to use.
}

var _ StageLike = &Stage[int, string]{}

func NewStage[IN, OUT any](
	name string,
	options ...stageOptions[IN, OUT],
) *Stage[IN, OUT] {
	outChSelector := func(data OUT) int {
		return 0
	}
	dummyIncomeCh := make(chan IN)
	dummyErrCh := make(chan error)
	s := &Stage[IN, OUT]{
		Name:          name,
		IncomingCh:    &dummyIncomeCh,
		ErrCh:         &dummyErrCh,
		OutChSelector: outChSelector,
	}
	for _, opt := range options {
		opt(s)
	}
	return s
}

type stageOptions[IN, OUT any] func(*Stage[IN, OUT])

func WithProcessFunction[IN, OUT any](
	processFunc func(IN) (OUT, error),
) stageOptions[IN, OUT] {
	return func(s *Stage[IN, OUT]) {
		s.ProcessFunc = processFunc
	}
}

func WithOutChannelSelector[IN, OUT any](
	outChSelector func(OUT) int,
) stageOptions[IN, OUT] {
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

// Resume resumes processing from this stage.
// This function creates new channels for the incoming data, error and stop channels.
func (s *Stage[IN, OUT]) Resume() {
	*s.IncomingCh = make(chan IN)
	*s.ErrCh = make(chan error)
	s.StopCh = make(chan none)
	go s.processThisStage()
}

// StopAndWait stops this and following stages by closing this stage's outgoing channel.
// This stage's outgoing channel is the same as the next stage's incoming channel.
// This function waits for the next stage to finish and returns any error.
func (s *Stage[IN, OUT]) StopAndWait() error {
	// Stop listening on other goroutines from the next stage's error channel.
	// Also stop sending data to the outgoing channel. This means effectively, stop the
	// working resume goroutine. We explicitly indicate the goroutine to finish and
	// not to read any state from the next stage. We will do that here.
	s.StopCh <- none{}

	return s.breakPipelineAndWait(nil)
}

func (s *Stage[IN, OUT]) breakPipelineAndWait(initialErr error) error {
	// Indicate next stage to stop.
	close(*s.OutgoingCh)
	// Read its status:
	err := <-*s.NextErrCh
	// Coalesce with any error at this stage.
	err = util.ErrorsCoalesce(initialErr, err)
	// Propagate error backwards.
	*s.ErrCh <- err
	// Close our own error channel.
	close(*s.ErrCh)
	// Close the stop channel indicator.
	close(s.StopCh)
	return err
}

func (s *Stage[IN, OUT]) processThisStage() {
	var foundError error
	var out OUT
readChannels:
	for {
		select {
		case data, ok := <-*s.IncomingCh:
			fmt.Printf("incoming %v at %s\n", data, s.Name)
			if !ok {
				// Incoming channel was closed. No data to be written to outgoing channel.
				fmt.Printf("breaking processing at %s\n", s.Name)
				break readChannels
			}
			out, foundError = s.ProcessFunc(data)
			if foundError != nil {
				fmt.Printf("ORIGINAL error at %s\n", s.Name)
				break readChannels
			}

			fmt.Printf("attempting to send %v at %s\n", out, s.Name)
			select {
			case *s.OutgoingCh <- out:
				// Success writing to the outgoing channel, nothing else to do.
			case foundError = <-*s.NextErrCh:
				// We received an error from next stage while trying to write to it.
				break readChannels
			case <-s.StopCh:
				// We have been instructed to stop, without reading any other channel.
				return
			}
			fmt.Printf("sent result %v at %s\n", out, s.Name)
			continue
		case foundError = <-*s.NextErrCh:
			fmt.Printf("got error from next stage at %s\n", s.Name)
			break readChannels
		case <-s.StopCh:
			// We have been instructed to stop, without reading any other channel.
			return
		}
	}

	// Discard the coalesced error, as the function below propagates the error backwards already.
	s.breakPipelineAndWait(foundError)

	fmt.Printf("done at %s\n", s.Name)
}

type none struct{}
