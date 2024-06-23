package updater

import (
	"context"
	"sync"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/db/mysql"
	"github.com/netsec-ethz/fpki/pkg/util"
)

// Manager contains multiple worker objects. It is able to work with several of them concurrently.
// The Manager has a dispatch function that determines, for each operation, which Conn should be
// used. This allows to split the e.g. certs, domains, etc into different workers, removing the
// possibility of deadlocks.
type Manager struct {
	Conn            db.Conn                         // DB
	MultiInsertSize int                             // amount of entries before calling the DB
	Stats           *Stats                          // Statistics about the update
	CertWorkers     []*CertWorker                   // shards for certificates
	DomainWorkers   []*DomainWorker                 // shards for domains
	ShardFuncCert   func(*common.SHA256Output) uint // select cert worker index from ID
	ShardFuncDomain func(*common.SHA256Output) uint // select the domain worker from domain ID

	IncomingCertChan   chan Certificate // Certificates arrive from this channel
	IncomingDomainChan chan DirtyDomain // Not a pointer! domains are taken ownership here.
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
	nBits := int(util.Log2(uint(workerCount - 1)))

	selectPartition := func(id *common.SHA256Output) uint {
		return mysql.PartitionByIdMSB(id, nBits)
	}

	m := &Manager{
		MultiInsertSize: multiInsertSize,
		Stats:           NewStatistics(statsUpdateFreq, statsUpdateFunc),
		ShardFuncCert:   selectPartition,
		ShardFuncDomain: selectPartition,
	}
	m.CertWorkers = make([]*CertWorker, workerCount)
	for i := 0; i < workerCount; i++ {
		m.CertWorkers[i] = NewCertWorker(ctx, i, m, conn)
	}
	m.DomainWorkers = make([]*DomainWorker, workerCount)
	for i := 0; i < workerCount; i++ {
		m.DomainWorkers[i] = NewDomainWorker(ctx, i, m, conn)
	}

	return m
}

func (m *Manager) Resume() {
	m.IncomingDomainChan = make(chan DirtyDomain)
	m.IncomingCertChan = make(chan Certificate)
	m.resumeDomainWorkers()
	m.resumeCertWorkers()

	// The rest of the resume is blocking, spawn a goroutine for it.
	go m.resume()
}

// Stop closes this manager's certificate incoming channel.
// This should cascade in the following events:
// 1. Manager closes the cert workers incoming channels.
// 2. Manager waits for the cert workers to finish.
// 3. Cert workers finish.
// 4. Manager closes the domain workers incoming channels.
// 5. Manager waits for the domain workers to finish.
// 6. Domain workers finish.
// 7. This pipeline is done.
func (m *Manager) Stop() {
	close(m.IncomingCertChan)
}

func (m *Manager) Wait() error {
	// If there is any error from the cert or domain workers, stop everything early.
	err := m.reportAnyError()
	if err != nil {
		// Stop all workers. This closes the incoming channel for all of them.
		m.stopCertWorkers()
		m.stopDomainWorkers()
	}

	// Report this error (or nil).
	return err
}

func (m *Manager) resume() {
	// The manager controls two pipelines:
	// 1. Read many Certificate and send each one to the appropriate Worker.
	// 2. Read many DirtyDomain and send each one to the appropriate Worker.
	// Note that in the first pipeline, the incoming channel will be closed by the previous step.
	// The incoming domains channel is used by the workers, who generate domains and send them
	// back to the manager for re-distribution.
	// Thus, in order to orderly stop the manager, the routine that reads certificates will
	// start a shutdown when the incoming certificates channel is closed.

	// Pipelines have to be opened in reverse.
	pipelineWaitGroup := sync.WaitGroup{}
	pipelineWaitGroup.Add(2) // Two concurrent pipelines

	// Second pipeline: domain workers read from here and send to the sink (the DB).
	go func() {
		// Second pipeline: move domains to workers' second pipeline.
		defer pipelineWaitGroup.Done()

		for d := range m.IncomingDomainChan {
			// Determine worker for the domain.
			w := m.ShardFuncDomain(&d.DomainID)
			m.DomainWorkers[w].IncomingChan <- d
		}

		// After closing the incoming domain channel, wait for all domains to be processed.
		m.stopDomainWorkers()
	}()

	// First pipeline: cert workers will read from here and send to the second pipeline.
	go func() {
		// First pipeline: move certificates to workers' first pipeline.
		// This action will cause the workers to move domains to this manager's second pipeline
		// (see below).
		defer pipelineWaitGroup.Done()

		for c := range m.IncomingCertChan {
			// Determine worker for the certificate.
			w := m.ShardFuncCert(&c.CertID)
			m.CertWorkers[w].IncomingChan <- c
		}

		m.stopCertWorkers()

		// Since all certificates have been processed already, no worker will send a domain
		// to the manager's incoming domain channel. We can close it now.
		// Closing it will trigger the shutdown of the second pipeline in this manager.
		close(m.IncomingDomainChan)
	}()

	// m.Stats.Start()
	pipelineWaitGroup.Wait()
}

func (m *Manager) resumeCertWorkers() {
	wg := sync.WaitGroup{}
	wg.Add(len(m.CertWorkers))

	for _, w := range m.CertWorkers {
		w := w
		go func() {
			defer wg.Done()
			w.Resume()
		}()
	}
	wg.Wait()
}

func (m *Manager) resumeDomainWorkers() {
	wg := sync.WaitGroup{}
	wg.Add(len(m.DomainWorkers))

	for _, w := range m.DomainWorkers {
		w := w
		go func() {
			defer wg.Done()
			w.Resume()
		}()
	}
	wg.Wait()
}

// stopCertWorkers waits for all workers to process all certificates.
// It closes their cert incoming channel, and waits for them to finish.
func (m *Manager) stopCertWorkers() {
	wg := sync.WaitGroup{}
	wg.Add(len(m.CertWorkers))

	for _, w := range m.CertWorkers {
		w := w
		go func() {
			defer wg.Done()
			w.Stop()
		}()
	}
	wg.Wait() // until we signaled all workers to stop.
}

func (m *Manager) stopDomainWorkers() {
	wg := sync.WaitGroup{}
	wg.Add(len(m.DomainWorkers))

	for _, w := range m.DomainWorkers {
		w := w
		go func() {
			defer wg.Done()
			w.Stop()
		}()
	}
	wg.Wait() // until we signaled all workers to stop.
}

// reportAnyError returns the first non nil error encountered, or nil if none was found.
func (m *Manager) reportAnyError() error {
	// The errFound channel will have the first non-nil error available, or nil if none to report.
	errFound := make(chan error)

	// We will use the wait group to wait for all reports.
	wg := sync.WaitGroup{}

	wg.Add(len(m.CertWorkers))
	for _, w := range m.CertWorkers {
		w := w
		go func() {
			defer wg.Done()
			if err := w.Wait(); err != nil {
				errFound <- err
				return
			}
		}()
	}

	wg.Add(len(m.DomainWorkers))
	for _, w := range m.DomainWorkers {
		w := w
		go func() {
			defer wg.Done()
			if err := w.Wait(); err != nil {
				errFound <- err // Report non-nil error.
			}
		}()
	}

	// Now, we wait for all the previous routines to finish, but in a goroutine.
	go func() {
		wg.Wait()
		// At this point, we finished waiting for all the reports and none had errors.
		// This means no routine wrote to errFound. Write nil here to unblock the function.
		errFound <- nil
	}()

	return <-errFound

}
