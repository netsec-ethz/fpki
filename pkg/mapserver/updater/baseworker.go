package updater

import (
	"context"
	"sync"

	"github.com/netsec-ethz/fpki/pkg/db"
)

type baseWorker struct {
	Id      int
	Ctx     context.Context
	Manager *Manager
	Conn    db.Conn
	errChan chan error     // errors are sent here. Only one error at a time.
	errWg   sync.WaitGroup // every time we send an error to errChan, we add 1 here.
}

func newBaseWorker(ctx context.Context, id int, m *Manager, conn db.Conn) *baseWorker {
	return &baseWorker{
		Id:      id,
		Ctx:     ctx,
		Manager: m,
		Conn:    conn,
		errWg:   sync.WaitGroup{},
	}
}

func (w *baseWorker) Resume() {
	w.errChan = make(chan error)
}

// Wait returns the last error or nil.
// The function waits until all errors have been reported.
// For that three things happen somewhere else:
// 1. Stop() has been called: the incomingChan channel is closed.
// 2. All pending errors have been reported.
// 3. closeErrors() has been called: the errChan is closed.
func (w *baseWorker) Wait() error {
	var err error
	for e := range w.errChan {
		if e != nil {
			err = e
			// deleteme test this and change comment of this function.
			break
		}
	}
	return err
}

// addError queues a new error to the errChan to be later retrieved via Wait().
func (w *baseWorker) addError(err error) {
	if err == nil {
		return
	}
	// We send it asynchronously because writing to errChan might block.
	w.errWg.Add(1)
	go func() {
		defer w.errWg.Done()
		w.errChan <- err
	}()
}

func (w *baseWorker) closeErrors() {
	// Wait until no other routine has to write to errChan.
	w.errWg.Wait()
	// No other routine will write to errChan, close it now.
	close(w.errChan)
}
