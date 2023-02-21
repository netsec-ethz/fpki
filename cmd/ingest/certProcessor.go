package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	lru "github.com/hashicorp/golang-lru"
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	"go.uber.org/atomic"
)

type CertificateNode struct {
	Cert   *ctx509.Certificate
	Parent *ctx509.Certificate
	IsLeaf bool
}

// CertBatch is an unwrapped collection of Certificate.
// All slices must have the same size.
type CertBatch struct {
	Names       [][]string // collection of names per certificate
	Expirations []*time.Time
	Certs       []*ctx509.Certificate
	Parents     []*ctx509.Certificate
	AreLeaves   []bool
}

func NewCertificateBatch() *CertBatch {
	return &CertBatch{
		Names:       make([][]string, 0, BatchSize),
		Expirations: make([]*time.Time, 0, BatchSize),
		Certs:       make([]*ctx509.Certificate, 0, BatchSize),
		Parents:     make([]*ctx509.Certificate, 0, BatchSize),
		AreLeaves:   make([]bool, 0, BatchSize),
	}
}

func (b *CertBatch) AddCertificate(c *CertificateNode) {
	b.Names = append(b.Names, updater.ExtractCertDomains(c.Cert))
	b.Expirations = append(b.Expirations, &c.Cert.NotAfter)
	b.Certs = append(b.Certs, c.Cert)
	b.Parents = append(b.Parents, c.Parent)
	b.AreLeaves = append(b.AreLeaves, c.IsLeaf)
}

func (b *CertBatch) IsFull() bool {
	return len(b.Certs) == BatchSize
}

// CertificateProcessor processes the insertion of certificate nodes into the DB.
// This is the most expensive stage, and as such, the processor prints the statistics about
// number of certificates and megabytes per second being inserted into the DB.
type CertificateProcessor struct {
	conn  db.Conn
	cache *lru.TwoQueueCache // IDs of certificates pushed to DB.

	updateCertBatch UpdateCertificateFunction // update strategy dependent method
	strategy        CertificateUpdateStrategy

	incomingCh    chan *CertificateNode // From the previous processor
	incomingBatch chan *CertBatch       // Ready to be inserted
	doneCh        chan struct{}
	// Statistics:
	writtenCerts  atomic.Int64
	writtenBytes  atomic.Int64
	uncachedCerts atomic.Int64
}

type CertificateUpdateStrategy int

const (
	CertificateUpdateOverwrite    CertificateUpdateStrategy = 0
	CertificateUpdateKeepExisting CertificateUpdateStrategy = 1
)

type UpdateCertificateFunction func(context.Context, db.Conn, [][]string, []*time.Time,
	[]*ctx509.Certificate, []*common.SHA256Output, []*ctx509.Certificate, []bool) error

func NewCertProcessor(conn db.Conn, incoming chan *CertificateNode,
	strategy CertificateUpdateStrategy) *CertificateProcessor {

	cache, err := lru.New2Q(LruCacheSize)
	if err != nil {
		panic(err)
	}
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
		cache:           cache,
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
		batch := NewCertificateBatch()
		for c := range p.incomingCh {
			batch.AddCertificate(c)
			if batch.IsFull() {
				p.incomingBatch <- batch
				batch = NewCertificateBatch()
			}
		}
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
			writtenCerts := p.writtenCerts.Load()
			writtenBytes := p.writtenBytes.Load()
			newCerts := p.uncachedCerts.Load()
			secondsSinceStart := float64(time.Since(startTime).Seconds())
			fmt.Printf("%.0f Certs / second (%.0f new), %.1f Mb/s\n",
				float64(writtenCerts)/secondsSinceStart,
				float64(newCerts)/secondsSinceStart,
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

func (p *CertificateProcessor) processBatch(batch *CertBatch) {
	// Compute the ID of the certs, and prepare the slices holding all the data.
	ids := updater.ComputeCertIDs(batch.Certs)
	names := make([][]string, 0, len(ids))
	expirations := make([]*time.Time, 0, len(ids))
	newIds := make([]*common.SHA256Output, 0, len(ids))
	certs := make([]*ctx509.Certificate, 0, len(ids))
	parents := make([]*ctx509.Certificate, 0, len(ids))
	areLeaves := make([]bool, 0, len(ids))

	// Check if the certificate has been already pushed to DB:
	for i, id := range ids {
		if !p.cache.Contains(*id) {
			// If the cache doesn't contain the certificate, we cannot skip it.
			names = append(names, batch.Names[i])
			expirations = append(expirations, batch.Expirations[i])
			newIds = append(newIds, ids[i])
			certs = append(certs, batch.Certs[i])
			parents = append(parents, batch.Parents[i])
			areLeaves = append(areLeaves, batch.AreLeaves[i])
		}
	}
	// Store certificates in DB:
	err := p.updateCertBatch(context.Background(), p.conn, names, expirations,
		certs, newIds, parents, areLeaves)
	if err != nil {
		panic(err)
	}

	// Update cache.
	for _, id := range ids {
		p.cache.Add(*id, nil)
	}

	// Update statistics.
	p.writtenCerts.Add(int64(len(batch.Certs)))
	p.uncachedCerts.Add(int64(len(newIds)))
	bytesInBatch := 0
	for i := range batch.Certs {
		bytesInBatch += len(batch.Certs[i].Raw)
		bytesInBatch += common.SHA256Size
		if batch.Parents[i] != nil {
			bytesInBatch += len(batch.Parents[i].Raw)
			bytesInBatch += common.SHA256Size
		}
	}
	p.writtenBytes.Add(int64(bytesInBatch))
}
