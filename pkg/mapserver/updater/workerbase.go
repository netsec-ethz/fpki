package updater

import (
	"context"
	"sync"

	"github.com/netsec-ethz/fpki/pkg/db"
)

type Worker struct {
	Id      int
	Ctx     context.Context
	Manager *Manager
	Conn    db.Conn
	errChan chan error     // errors are sent here. Only one error at a time.
	errWg   sync.WaitGroup // every time we send an error to errChan, we add 1 here.
}

func newBaseWorker(ctx context.Context, id int, m *Manager, conn db.Conn) *Worker {
	return &Worker{
		Id:      id,
		Ctx:     ctx,
		Manager: m,
		Conn:    conn,
		errChan: make(chan error),
		errWg:   sync.WaitGroup{},
	}
}

// Wait returns the last error or nil.
// The function waits until all errors have been reported.
// For that three things happen somewhere else:
// 1. Stop() has been called: the incomingChan channel is closed.
// 2. All pending errors have been reported.
// 3. closeErrors() has been called: the errChan is closed.
func (w *Worker) Wait() error {
	var err error
	for e := range w.errChan {
		if e != nil {
			err = e
		}
	}
	return err
}

// addError queues a new error to the errChan to be later retrieved via Wait().
func (w *Worker) addError(err error) {
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

func (w *Worker) closeErrors() {
	// Wait until no other routine has to write to errChan.
	w.errWg.Wait()
	// No other routine will write to errChan, close it now.
	close(w.errChan)
}
