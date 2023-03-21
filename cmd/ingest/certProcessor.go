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
	"go.uber.org/atomic"
)

type CertificateNode struct {
	CertID   *common.SHA256Output
	Cert     *ctx509.Certificate
	ParentID *common.SHA256Output
	IsLeaf   bool
}

// CertBatch is an unwrapped collection of Certificate.
// All slices must have the same size.
type CertBatch struct {
	Names       [][]string // collection of names per certificate
	Expirations []*time.Time
	Certs       []*ctx509.Certificate
	CertIDs     []*common.SHA256Output
	ParentIDs   []*common.SHA256Output
	AreLeaves   []bool
}

func NewCertificateBatch() *CertBatch {
	return &CertBatch{
		Names:       make([][]string, 0, BatchSize),
		Expirations: make([]*time.Time, 0, BatchSize),
		Certs:       make([]*ctx509.Certificate, 0, BatchSize),
		CertIDs:     make([]*common.SHA256Output, 0, BatchSize),
		ParentIDs:   make([]*common.SHA256Output, 0, BatchSize),
		AreLeaves:   make([]bool, 0, BatchSize),
	}
}

func (b *CertBatch) AddCertificate(c *CertificateNode) {
	b.Names = append(b.Names, updater.ExtractCertDomains(c.Cert))
	b.Expirations = append(b.Expirations, &c.Cert.NotAfter)
	b.Certs = append(b.Certs, c.Cert)
	b.CertIDs = append(b.CertIDs, c.CertID)
	b.ParentIDs = append(b.ParentIDs, c.ParentID)
	b.AreLeaves = append(b.AreLeaves, c.IsLeaf)
}

func (b *CertBatch) IsFull() bool {
	return len(b.Certs) == BatchSize
}

// CertificateProcessor processes the insertion of certificate nodes into the DB.
// This is the most expensive stage, and as such, the processor prints the statistics about
// number of certificates and megabytes per second being inserted into the DB.
type CertificateProcessor struct {
	conn db.Conn

	updateCertBatch UpdateCertificateFunction // update strategy dependent method
	strategy        CertificateUpdateStrategy

	incomingCh    chan *CertificateNode // From the previous processor
	incomingBatch chan *CertBatch       // Ready to be inserted
	doneCh        chan struct{}
	// Statistics:
	ReadCerts     atomic.Int64
	ReadBytes     atomic.Int64
	UncachedCerts atomic.Int64
}

type CertificateUpdateStrategy int

const (
	CertificateUpdateOverwrite    CertificateUpdateStrategy = 0
	CertificateUpdateKeepExisting CertificateUpdateStrategy = 1
)

type UpdateCertificateFunction func(context.Context, db.Conn, [][]string, []*time.Time,
	[]*ctx509.Certificate, []*common.SHA256Output, []*common.SHA256Output, []bool) error

func NewCertProcessor(conn db.Conn, incoming chan *CertificateNode,
	strategy CertificateUpdateStrategy) *CertificateProcessor {

	// Select the update certificate method depending on the strategy:
	var updateFcn UpdateCertificateFunction
	switch strategy {
	case CertificateUpdateOverwrite:
		updateFcn = updater.UpdateCertsWithOverwrite
	case CertificateUpdateKeepExisting:
		updateFcn = updater.UpdateCertsWithKeepExisting
	default:
		panic(fmt.Errorf("invalid strategy %v", strategy))
	}

	p := &CertificateProcessor{
		conn:            conn,
		updateCertBatch: updateFcn,
		strategy:        strategy,
		incomingCh:      incoming,
		incomingBatch:   make(chan *CertBatch),
		doneCh:          make(chan struct{}),
	}

	p.start()
	return p
}

// start starts the pipeline.
// Two stages in this processor: from certificate node to batch, and from batch to DB.
func (p *CertificateProcessor) start() {
	// Prepare DB for certificate update.
	p.PrepareDB()

	// Start pipeline.
	go func() {
		wg := sync.WaitGroup{}
		wg.Add(NumDBWriters)
		for w := 0; w < NumDBWriters; w++ {
			go func() {
				defer wg.Done()
				p.createBatches()
			}()
		}
		wg.Wait()
		// Because the stage is finished, close the output channel:
		close(p.incomingBatch)
	}()

	go func() {
		wg := sync.WaitGroup{}
		wg.Add(NumDBWriters)
		for w := 0; w < NumDBWriters; w++ {
			go func() {
				defer wg.Done()
				for batch := range p.incomingBatch {
					p.processBatch(batch)
				}
			}()
		}
		wg.Wait()
		// Leave the DB ready again.
		p.ConsolidateDB()
		// This pipeline is finished, signal it.
		p.doneCh <- struct{}{}
	}()

	// Statistics.
	ticker := time.NewTicker(2 * time.Second)
	startTime := time.Now()
	go func() {
		for {
			select {
			case <-ticker.C:
			case <-p.doneCh:
				p.doneCh <- struct{}{} // signal again
				return
			}
			writtenCerts := p.ReadCerts.Load()
			writtenBytes := p.ReadBytes.Load()
			uncachedCerts := p.UncachedCerts.Load()
			secondsSinceStart := float64(time.Since(startTime).Seconds())
			fmt.Printf("%.0f Certs/s (%.0f%% uncached), %.1f Mb/s\n",
				float64(writtenCerts)/secondsSinceStart,
				float64(uncachedCerts)*100./float64(writtenCerts),
				float64(writtenBytes)/1024./1024./secondsSinceStart,
			)
		}
	}()
}

func (p *CertificateProcessor) Wait() {
	<-p.doneCh
}

// PrepareDB prepares the DB for certificate insertion. This could imply dropping keys,
// disabling indices, etc. depending on the update strategy.
// Before the DB is functional again, it needs a call to ConsolidateDB.
func (p *CertificateProcessor) PrepareDB() {
	switch p.strategy {
	case CertificateUpdateOverwrite:
		// Try to remove unique index `id` and primary key. They may not exist.
		if _, err := p.conn.DB().Exec("ALTER TABLE certs DROP PRIMARY KEY"); err != nil {
			panic(fmt.Errorf("disabling keys: %s", err))
		}
	}
}

// ConsolidateDB finishes the certificate update process and leaves the DB ready again.
func (p *CertificateProcessor) ConsolidateDB() {
	switch p.strategy {
	case CertificateUpdateOverwrite:
		// Reenable keys:
		fmt.Println("Reenabling keys in DB.certs ... ")
		str := "DROP TABLE IF EXISTS certs_aux_tmp"
		if _, err := p.conn.DB().Exec(str); err != nil {
			panic(fmt.Errorf("reenabling keys: %s", err))
		}
		str = "CREATE TABLE certs_aux_tmp LIKE certs;"
		if _, err := p.conn.DB().Exec(str); err != nil {
			panic(fmt.Errorf("reenabling keys: %s", err))
		}
		str = "ALTER TABLE certs_aux_tmp ADD PRIMARY KEY (id)"
		if _, err := p.conn.DB().Exec(str); err != nil {
			panic(fmt.Errorf("reenabling keys: %s", err))
		}
		str = "INSERT IGNORE INTO certs_aux_tmp SELECT * FROM certs"
		if _, err := p.conn.DB().Exec(str); err != nil {
			panic(fmt.Errorf("reenabling keys: %s", err))
		}
		str = "DROP TABLE certs"
		if _, err := p.conn.DB().Exec(str); err != nil {
			panic(fmt.Errorf("reenabling keys: %s", err))
		}
		str = "ALTER TABLE certs_aux_tmp RENAME TO certs"
		if _, err := p.conn.DB().Exec(str); err != nil {
			panic(fmt.Errorf("reenabling keys: %s", err))
		}
	}
}

// createBatches reads CertificateNodes from the incoming channel and sends them in batches
// to processing.
func (p *CertificateProcessor) createBatches() {
	batch := NewCertificateBatch()
	for c := range p.incomingCh {
		batch.AddCertificate(c)
		if batch.IsFull() {
			p.incomingBatch <- batch
			batch = NewCertificateBatch()
		}
	}
	// Last batch (might be empty).
	p.incomingBatch <- batch
}

func (p *CertificateProcessor) processBatch(batch *CertBatch) {
	// Store certificates in DB:
	err := p.updateCertBatch(context.Background(), p.conn, batch.Names, batch.Expirations,
		batch.Certs, batch.CertIDs, batch.ParentIDs, batch.AreLeaves)
	if err != nil {
		panic(err)
	}
}
