package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
)

// CertBatch is an unwrapped collection of Certificate.
// All slices must have the same size.
type CertBatch struct {
	Names       [][]string // collection of names per certificate
	Expirations []time.Time
	Certs       []ctx509.Certificate
	CertIDs     []common.SHA256Output
	ParentIDs   []*common.SHA256Output
}

func NewCertificateBatch() CertBatch {
	return CertBatch{
		Names:       make([][]string, 0, MultiInsertSize),
		Expirations: make([]time.Time, 0, MultiInsertSize),
		Certs:       make([]ctx509.Certificate, 0, MultiInsertSize),
		CertIDs:     make([]common.SHA256Output, 0, MultiInsertSize),
		ParentIDs:   make([]*common.SHA256Output, 0, MultiInsertSize),
	}
}

func (b *CertBatch) AddCertificate(c updater.Certificate) {
	b.Names = append(b.Names, c.Names)
	b.Expirations = append(b.Expirations, c.Cert.NotAfter)
	b.Certs = append(b.Certs, c.Cert)
	b.CertIDs = append(b.CertIDs, c.CertID)
	b.ParentIDs = append(b.ParentIDs, c.ParentID)
}

func (b *CertBatch) IsFull() bool {
	return len(b.Certs) == MultiInsertSize
}

// CertificateProcessor processes the insertion of certificate nodes into the DB.
// This is the most expensive stage, and as such, the processor prints the statistics about
// number of certificates and megabytes per second being inserted into the DB.
type CertificateProcessor struct {
	conn db.Conn

	updateCertBatch UpdateCertificateFunction // update strategy dependent method
	strategy        CertificateUpdateStrategy

	incomingCh chan updater.Certificate // From the previous processor
	batchCh    chan CertBatch           // Ready to be inserted
	doneCh     chan struct{}

	stats *updater.Stats // Statistics
}

type CertificateUpdateStrategy int

const (
	CertificateUpdateOverwrite    CertificateUpdateStrategy = 0
	CertificateUpdateKeepExisting CertificateUpdateStrategy = 1
)

type UpdateCertificateFunction func(context.Context, db.Conn, [][]string,
	[]common.SHA256Output, []*common.SHA256Output, []ctx509.Certificate, []time.Time,
	[]common.PolicyDocument) error

func NewCertProcessor(conn db.Conn, incoming chan updater.Certificate,
	strategy CertificateUpdateStrategy) *CertificateProcessor {

	// Select the update certificate method depending on the strategy:
	var updateFcn UpdateCertificateFunction
	switch strategy {
	case CertificateUpdateOverwrite:
		updateFcn = updater.UpdateWithOverwrite
	case CertificateUpdateKeepExisting:
		updateFcn = updater.UpdateWithKeepExisting
	default:
		panic(fmt.Errorf("invalid strategy %v", strategy))
	}

	p := &CertificateProcessor{
		conn:            conn,
		updateCertBatch: updateFcn,
		strategy:        strategy,
		stats:           updater.NewStatistics(2*time.Second, printStats),
	}
	p.Resume(incoming)

	return p
}

// Resume starts or continues the pipeline.
// Two stages in this processor: from certificate node to batch, and from batch to DB.
func (p *CertificateProcessor) Resume(incoming chan updater.Certificate) {
	// Prepare DB for certificate update.
	p.PrepareDB()

	// Prepare pipeline structure.
	// Incoming receives the parsed certificates from the previous pipeline (Processor).
	p.incomingCh = incoming
	// batchCh receives batches of certificates from the previous channel.
	p.batchCh = make(chan CertBatch)
	// doneCh indicates all the batches are updated in DB.
	p.doneCh = make(chan struct{})

	// Create batches. Two workers are enough.
	go func() {
		const numWorkers = 1
		wg := sync.WaitGroup{}
		wg.Add(numWorkers)
		for w := 0; w < numWorkers; w++ {
			go func() {
				defer wg.Done()
				p.createBatches() // from incomingCh -> batchCh
			}()
		}
		wg.Wait()
		// Because the stage is finished, close the output channel:
		close(p.batchCh)
	}()

	// Read batches and call the next step of the pipeline.
	go func() {
		wg := sync.WaitGroup{}
		wg.Add(NumDBWriters)
		for w := 0; w < NumDBWriters; w++ {
			w := w
			go func() {
				defer wg.Done()
				for batch := range p.batchCh {
					p.processBatch(w, batch) // from batchCh
				}
			}()
		}
		wg.Wait()

		// Stop printing the stats.
		p.stats.Stop()

		// Leave the DB ready again.
		p.ConsolidateDB()

		// This pipeline is finished, signal it.
		p.doneCh <- struct{}{}
	}()

	// Statistics.
	p.stats.Start()
}

func (p *CertificateProcessor) Wait() {
	<-p.doneCh
}

// PrepareDB is a noop (for InnoDB).
func (p *CertificateProcessor) PrepareDB() {}

// ConsolidateDB is a noop (for InnoDB).
func (p *CertificateProcessor) ConsolidateDB() {}

// createBatches reads CertificateNodes from the incoming channel and sends them in batches
// to processing.
func (p *CertificateProcessor) createBatches() {
	batch := NewCertificateBatch()
	for c := range p.incomingCh {
		batch.AddCertificate(c)
		if batch.IsFull() {
			p.batchCh <- batch
			batch = NewCertificateBatch()
		}
	}
	// Last batch (might be empty).
	p.batchCh <- batch
}

func (p *CertificateProcessor) processBatch(workerID int, batch CertBatch) {
	// Store certificates in DB:
	fmt.Printf("DB: [worker %d][%s] processing batch (len=%d)...\n",
		workerID, time.Now().Format(time.StampMilli), len(batch.CertIDs))
	err := p.updateCertBatch(context.Background(), p.conn, batch.Names,
		batch.CertIDs, batch.ParentIDs, batch.Certs, batch.Expirations, nil)
	if err != nil {
		panic(err)
	}
	fmt.Printf("DB: [worker %d][%s] finished batch.\n",
		workerID, time.Now().Format(time.StampMilli))
}
