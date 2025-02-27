package updater

import (
	"sync/atomic"
	"time"
)

// Stats keeps statistics for the update process.
type Stats struct {
	CreateTime    time.Time
	LastStartTime time.Time
	ReadCerts     atomic.Int64
	ReadBytes     atomic.Int64
	UncachedCerts atomic.Int64
	WrittenCerts  atomic.Int64
	WrittenBytes  atomic.Int64

	TotalFiles     atomic.Int64
	TotalFilesRead atomic.Int64

	updateFreq  time.Duration
	updateFunc  func(*Stats)
	statsTicker *time.Ticker
}

// NewStatistics returns a new statistics object that calls the update function every `frequency`.
func NewStatistics(
	updateFreq time.Duration,
	updateFunc func(*Stats),
) *Stats {
	// Ensure that we have a valid function to call.
	if updateFunc == nil {
		updateFunc = func(s *Stats) {} // do nothing update function
	}
	stats := &Stats{
		CreateTime:  time.Now(),
		updateFreq:  updateFreq,
		updateFunc:  updateFunc,
		statsTicker: time.NewTicker(updateFreq),
	}
	stats.Start()

	return stats
}

func (s *Stats) Start() {
	s.LastStartTime = time.Now()
	s.statsTicker.Reset(s.updateFreq)
	go func() {
		for {
			<-s.statsTicker.C
			s.updateFunc(s)
		}
	}()
}

func (s *Stats) Stop() {
	s.statsTicker.Stop()
}
