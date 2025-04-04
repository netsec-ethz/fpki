package sync

import (
	"runtime"
	"sync/atomic"
)

type SpinLock struct {
	workerCount int
	activeID    atomic.Int32
	finishedID  atomic.Int32
}

func NewSpinLock(workerCount int) *SpinLock {
	l := &SpinLock{
		workerCount: workerCount,
	}
	l.activeID.Store(-1)
	l.finishedID.Store(-1)
	return l
}

func (l *SpinLock) Start() {
	go func() {
		for w := range l.workerCount {
			l.activeID.Store(int32(w))
			// Wait until done.
			for l.finishedID.Load() != int32(w) {
				runtime.Gosched()
			}
		}
	}()
}

func (l *SpinLock) Wait() {
	for l.finishedID.Load() != int32(l.workerCount-1) {
		runtime.Gosched()
	}
}

func (l *SpinLock) Lock(id int) {
	for l.activeID.Load() != int32(id) {
		runtime.Gosched()
	}
}

func (l *SpinLock) UnLock(id int) {
	l.finishedID.Store(int32(id))
}
