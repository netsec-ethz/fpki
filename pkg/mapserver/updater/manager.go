package updater

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/db/mysql"
)

// Manager contains multiple db.Conn objects. It is able to work with several of them concurrently.
// The Manager has a dispatch function that determines, for each operation, which Conn should be
// used. This allows to split the e.g. certs, domains, etc into different ones, removing the
// possibility of deadlocks.
type Manager struct {
	Conn            db.Conn                         // DB
	MultiInsertSize int                             // amount of entries before calling the DB
	Stats           *Stats                          // Statistics about the update
	CertWorkers     []*WorkerCerts                  // sharding ends up picking one of these
	DomainWorkers   []*WorkerDomains                // shards for domains
	ShardFuncCert   func(*common.SHA256Output) uint // select cert worker index from ID
	ShardFuncDomain func(*common.SHA256Output) uint // select the domain worker from domain ID

	IncomingCertChan   chan *Certificate // Certificates arrive from this channel
	IncomingDomainChan chan *DirtyDomain
	stopping           atomic.Bool // Set to true when there is no more data in IncomingCertChan
	doneChan           chan struct{}
}

// NewManager creates a new manager and its workers.
// The context ctx is used thru the lifetime of the workers, to perform DB operations, etc.
func NewManager(
	ctx context.Context,
	workerCount int,
	conn db.Conn,
	multiInsertSize int,
	statsUpdateFreq time.Duration,
	statsUpdateFunc func(*Stats),
) *Manager {
	// Compute how many bits we need to cover N partitions (i.e. ceil(log2(N-1)),
	// doable by computing the bit length of N-1 even if not a power of 2.
	nBits := 0
	for n := workerCount - 1; n > 0; n >>= 1 {
		nBits++
	}

	selectPartition := func(id *common.SHA256Output) uint {
		return mysql.PartitionByIdMSB(id, nBits)
	}

	m := &Manager{
		MultiInsertSize:    multiInsertSize,
		Stats:              NewStatistics(statsUpdateFreq, statsUpdateFunc),
		ShardFuncCert:      selectPartition,
		ShardFuncDomain:    selectPartition,
		IncomingCertChan:   make(chan *Certificate),
		IncomingDomainChan: make(chan *DirtyDomain),
		doneChan:           make(chan struct{}),
	}
	m.CertWorkers = make([]*WorkerCerts, workerCount)
	for i := 0; i < workerCount; i++ {
		m.CertWorkers[i] = NewWorkerCerts(ctx, i, m, conn)
	}
	m.DomainWorkers = make([]*WorkerDomains, workerCount)
	for i := 0; i < workerCount; i++ {
		m.DomainWorkers[i] = NewWorkerDomains(ctx, i, m, conn)
	}
	m.Resume()

	return m
}

func (m *Manager) ProcessCertificates(certs []*Certificate) {
	for _, c := range certs {
		m.IncomingCertChan <- c
	}
	close(m.IncomingCertChan)
	// go m.resume()
}

func (m *Manager) Resume() {
	go m.resume()
}

func (m *Manager) resume() {
	m.Stats.Start()

	// The manager controls two pipelines:
	// 1. Read many Certificate and send each one to the appropriate Worker.
	// 2. Read many DirtyDomain and send each one to the appropriate Worker.
	// Note that in the first pipeline, the incoming channel will be closed by the previous step.
	// The incoming domains channel is used by the workers, who generate domains and send them
	// back to the manager for re-distribution.
	// Thus, in order to orderly stop the manager, the routine that reads certificates will
	// start a shutdown when the incoming certificates channel is closed.
	// For that, the manager flushes all workers; some certificates will be written, some domains
	// will arrive to the manager.

	wg := sync.WaitGroup{}
	wg.Add(2) // Two concurrent pipelines

	go func() {
		// First pipeline: move certificates to workers' first pipeline.
		// This action will cause the workers to move domains to this manager's second pipeline
		// (see below).
		defer wg.Done()

		for c := range m.IncomingCertChan {
			// Determine worker for the certificate.
			w := m.ShardFuncCert(c.CertID)
			m.CertWorkers[w].IncomingCert <- c
		}
		m.stopping.Store(true) // Whenever the workers check, tell them we are stopping now.
		fmt.Printf("deleteme stopping manager now: %v\n", m.stopping.Load())
		m.waitForAllCertificates()
		// Since all certificates have been processed already, no worker will send a domain
		// to the manager's incoming domain channel. We can close it now.
		// Closing it will trigger the shutdown of the second pipeline in this manager.
		fmt.Println("deleteme about to close domain dispatch")
		close(m.IncomingDomainChan)
	}()

	go func() {
		// Second pipeline: move domains to workers' second pipeline.
		defer wg.Done()

		for d := range m.IncomingDomainChan {
			// Determine worker for the domain.
			w := m.ShardFuncDomain(d.DomainID)
			m.DomainWorkers[w].IncomingDomain <- d
		}
		// After closing the incoming domain channel, flush all domains in all workers,
		// and wait for all domains to be processed.
		m.waitForAllDomains()
	}()
	wg.Wait()

	m.Stats.Stop()           // stop statistics printing
	m.doneChan <- struct{}{} // Unblock any previous steps in the pipeline
}

func (m *Manager) Wait() {
	<-m.doneChan
}

func (m *Manager) Flush() {
	m.flushAllWorkers()
}

func (m *Manager) flushAllWorkers() {
	wg := sync.WaitGroup{}
	wg.Add(len(m.CertWorkers))

	for _, w := range m.CertWorkers {
		w := w
		go func() {
			defer wg.Done()
			w.Flush()
		}()
	}
	wg.Wait()
}

// waitForAllCertificates waits for all workers to process all certificates.
// It signals the workers to flush their certificates, and waits for them until they stop
// reading their incoming certificate pipeline.
// After all certificates have been processed, it closes the workers' incoming certificate channel.
func (m *Manager) waitForAllCertificates() {
	fmt.Println("deleteme waiting for all certificates")
	wg := sync.WaitGroup{}
	wg.Add(len(m.CertWorkers))

	for _, w := range m.CertWorkers {
		w := w
		go func() {
			defer wg.Done()
			w.FlushCerts() // this blocks until the worker has read the signal.
			w.WaitCerts()
		}()
	}
	wg.Wait() // until all workers have processed all certs

	// Now the workers are not reading from their incoming certs channel. Close them.
	for _, w := range m.CertWorkers {
		close(w.IncomingCert)
	}
}

func (m *Manager) waitForAllDomains() {
	wg := sync.WaitGroup{}
	wg.Add(len(m.DomainWorkers))

	for _, w := range m.DomainWorkers {
		w := w
		go func() {
			defer wg.Done()
			w.FlushDomains() // this blocks until the worker has read the signal.
			w.WaitDomains()
		}()
	}
	wg.Wait() // until all workers have processed all certs

	// Workers are not reading from their incoming domains channel. Close them.
	for _, w := range m.DomainWorkers {
		close(w.IncomingDomain)
	}
}
