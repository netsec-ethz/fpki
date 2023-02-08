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
	Names  []string // collection of names per certificate
	Cert   *ctx509.Certificate
	Parent *ctx509.Certificate
}

// CertBatch is an unwrapped collection of Certificate.
// All slices must have the same size.
type CertBatch struct {
	Names   [][]string // collection of names per certificate
	Certs   []*ctx509.Certificate
	Parents []*ctx509.Certificate
}

func NewCertificateBatch() *CertBatch {
	return &CertBatch{
		Names:   make([][]string, 0, BatchSize),
		Certs:   make([]*ctx509.Certificate, 0, BatchSize),
		Parents: make([]*ctx509.Certificate, 0, BatchSize),
	}
}

func (b *CertBatch) AddCertificate(c *CertificateNode) {
	b.Names = append(b.Names, c.Names)
	b.Certs = append(b.Certs, c.Cert)
	b.Parents = append(b.Parents, c.Parent)
}

func (b *CertBatch) IsFull() bool {
	return len(b.Certs) == BatchSize
}

// CertificateProcessor processes the insertion of certificate nodes into the DB.
// This is the most expensive stage, and as such, the processor prints the statistics about
// number of certificates and megabytes per second being inserted into the DB.
type CertificateProcessor struct {
	conn db.Conn

	incomingCh    chan *CertificateNode // From the previous processor
	incomingBatch chan *CertBatch       // Ready to be inserted
	doneCh        chan struct{}
	// Statistics:
	writtenCerts atomic.Int64
	writtenBytes atomic.Int64
}

func NewBatchProcessor(conn db.Conn, incoming chan *CertificateNode) *CertificateProcessor {
	p := &CertificateProcessor{
		conn:          conn,
		incomingCh:    incoming,
		incomingBatch: make(chan *CertBatch),
		doneCh:        make(chan struct{}),
	}
	p.start()
	return p
}

// start starts the pipeline.
// Two stages in this processor: from certificate node to batch, and from batch to DB.
func (p *CertificateProcessor) start() {
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
		// This stage is finished, indicate so.
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
				return
			}
			writtenCerts := p.writtenCerts.Load()
			writtenBytes := p.writtenBytes.Load()
			secondsSinceStart := float64(time.Since(startTime).Seconds())
			fmt.Printf("%.0f Certs / second, %.1f Mb/s\n",
				float64(writtenCerts)/secondsSinceStart,
				float64(writtenBytes)/1024./1024./secondsSinceStart,
			)
		}
	}()
}

func (p *CertificateProcessor) Wait() {
	<-p.doneCh
}

func (p *CertificateProcessor) processBatch(batch *CertBatch) {
	// Store certificates in DB:
	err := updater.UpdateCerts(context.Background(), p.conn, batch.Names, batch.Certs, batch.Parents)
	if err != nil {
		panic(err)
	}
	p.writtenCerts.Add(int64(len(batch.Certs)))
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

	// TODO(juagargi) push entries to the dirty table
}
