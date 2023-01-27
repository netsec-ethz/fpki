package main

import (
	"context"
	"fmt"
	"sync"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
)

const BatchSize = 1000

type Batch struct {
	Certs  []*ctx509.Certificate
	Chains [][]*ctx509.Certificate
}

func NewBatch() *Batch {
	return &Batch{
		Certs:  make([]*ctx509.Certificate, 0, BatchSize),
		Chains: make([][]*ctx509.Certificate, 0, BatchSize),
	}
}

// AddCert pushed the cert data into the batch.
func (b *Batch) AddCert(d *CertData) {
	b.Certs = append(b.Certs, d.Cert)
	b.Chains = append(b.Chains, d.CertChain)
}

func (b *Batch) Full() bool {
	return len(b.Certs) == BatchSize
}

type BatchProcessor struct {
	conn db.Conn

	incomingCh chan *Batch
	incomingWg sync.WaitGroup
	doneCh     chan struct{}
}

func NewBatchProcessor(conn db.Conn) *BatchProcessor {
	p := &BatchProcessor{
		conn:       conn,
		incomingCh: make(chan *Batch),
		doneCh:     make(chan struct{}),
	}
	p.start()
	return p
}

func (p *BatchProcessor) start() {
	db := p.conn.DB()
	_ = db
	ini := func() {
		// _, err := db.Exec("LOCK TABLES certs WRITE;")
		// if err != nil {
		// 	panic(err)
		// }
		// if _, err := db.Exec("SET autocommit=0"); err != nil {
		// 	panic(err)
		// }
		// if _, err := db.Exec("ALTER TABLE certs DISABLE KEYS"); err != nil {
		// 	panic(err)
		// }
		if _, err := db.Exec("ALTER TABLE certs DROP INDEX id"); err != nil {
			panic(err)
		}
	}
	end := func() {

		fmt.Println("deleteme before enabling keys")
		if _, err := db.Exec("ALTER TABLE certs ADD UNIQUE INDEX id (id ASC)"); err != nil {
			panic(err)
		}
		// if _, err := db.Exec("ALTER TABLE certs ENABLE KEYS"); err != nil {
		// 	panic(err)
		// }
		fmt.Println("deleteme keys enabled.")

		fmt.Println("deleteme about to commit all changes")
		// if _, err := db.Exec("COMMIT"); err != nil {
		// 	panic(err)
		// }
		fmt.Println("deleteme commit succeeded.")
		// if _, err := db.Exec("UNLOCK TABLES"); err != nil {
		// 	panic(err)
		// }
	}

	ini()
	go func() {
		for batch := range p.incomingCh {
			go p.wrapBatch(batch)
		}
		end()
		p.doneCh <- struct{}{}
	}()
}

func (p *BatchProcessor) Wait() {
	fmt.Println("deleteme waiting 1")
	p.incomingWg.Wait()
	close(p.incomingCh)
	fmt.Println("deleteme waiting 2")
	<-p.doneCh
	fmt.Println("deleteme waiting 3")
}

// Process processes a Batch into the DB.
func (p *BatchProcessor) Process(b *Batch) {
	p.incomingWg.Add(1) // one more batch to process
	go func() {
		p.incomingCh <- b
	}()
}

// wrapBatch protects the processing of a batch.
func (p *BatchProcessor) wrapBatch(batch *Batch) {
	defer p.incomingWg.Done() // one less batch to process
	p.processBatch(batch)
	fmt.Println("batch processed")
}

func (p *BatchProcessor) processBatch(batch *Batch) {
	// Store certificates in DB:
	err := updater.UpdateCerts(context.Background(), p.conn, batch.Certs, batch.Chains)
	if err != nil {
		panic(err)
	}
	// TODO(juagargi) push entries to the dirty table
}
