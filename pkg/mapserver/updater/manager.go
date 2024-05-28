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

	IncomingCertChan chan *Certificate // Certificates arrive from this channel
	// deleteme incomindomains should be private
	IncomingDomainChan chan *DirtyDomain
	errChan            chan error
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
		MultiInsertSize:    multiInsertSize,
		Stats:              NewStatistics(statsUpdateFreq, statsUpdateFunc),
		ShardFuncCert:      selectPartition,
		ShardFuncDomain:    selectPartition,
		IncomingCertChan:   make(chan *Certificate),
		IncomingDomainChan: make(chan *DirtyDomain),
		errChan:            make(chan error),
	}
	m.CertWorkers = make([]*CertWorker, workerCount)
	for i := 0; i < workerCount; i++ {
		m.CertWorkers[i] = NewCertWorker(ctx, i, m, conn)
	}
	m.DomainWorkers = make([]*DomainWorker, workerCount)
	for i := 0; i < workerCount; i++ {
		m.DomainWorkers[i] = NewDomainWorker(ctx, i, m, conn)
	}
	m.Resume()

	return m
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

	wg := sync.WaitGroup{}
	wg.Add(2) // Two concurrent pipelines

	var errInCerts error
	var errInDomains error
	go func() {
		// First pipeline: move certificates to workers' first pipeline.
		// This action will cause the workers to move domains to this manager's second pipeline
		// (see below).
		defer wg.Done()

		for c := range m.IncomingCertChan {
			// Determine worker for the certificate.
			w := m.ShardFuncCert(c.CertID)
			m.CertWorkers[w].IncomingChan <- c
		}

		errInCerts = m.stopAndWaitForCertWorkers()

		// Since all certificates have been processed already, no worker will send a domain
		// to the manager's incoming domain channel. We can close it now.
		// Closing it will trigger the shutdown of the second pipeline in this manager.
		close(m.IncomingDomainChan)
	}()

	go func() {
		// Second pipeline: move domains to workers' second pipeline.
		defer wg.Done()

		for d := range m.IncomingDomainChan {
			// Determine worker for the domain.
			w := m.ShardFuncDomain(d.DomainID)
			m.DomainWorkers[w].IncomingChan <- d
		}

		// After closing the incoming domain channel, wait for all domains to be processed.
		errInDomains = m.stopAndWaitForDomainWorkers()
	}()
	wg.Wait()

	m.Stats.Stop() // stop statistics printing

	// Unblock any previous steps in the pipeline and return last error
	m.errChan <- util.ErrorsCoalesce(errInCerts, errInDomains)
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
	return <-m.errChan
}

// stopAndWaitForCertWorkers waits for all workers to process all certificates.
// It closes their cert incoming channel, and waits for them to finish.
func (m *Manager) stopAndWaitForCertWorkers() error {
	wg := sync.WaitGroup{}
	wg.Add(len(m.CertWorkers))

	errors := make([]error, len(m.CertWorkers))
	for i, w := range m.CertWorkers {
		i, w := i, w
		go func() {
			defer wg.Done()
			w.Stop()
			errors[i] = w.Wait()
		}()
	}
	wg.Wait() // until all workers have processed all certs
	return util.ErrorsCoalesce(errors...)
}

func (m *Manager) stopAndWaitForDomainWorkers() error {
	wg := sync.WaitGroup{}
	wg.Add(len(m.DomainWorkers))

	errors := make([]error, len(m.CertWorkers))
	for i, w := range m.DomainWorkers {
		i, w := i, w
		go func() {
			defer wg.Done()
			w.Stop()
			errors[i] = w.Wait()
		}()
	}
	wg.Wait() // until all workers have processed all domains
	return util.ErrorsCoalesce(errors...)
}
