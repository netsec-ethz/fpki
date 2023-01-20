package main

import (
	"fmt"
	"sync"
	"sync/atomic"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
)

const BatchSize = 10000

type Batch struct {
	Certs  []*ctx509.Certificate
	Chains [][]*ctx509.Certificate
	cns    []*string
}

func NewBatch() *Batch {
	return &Batch{
		Certs:  make([]*ctx509.Certificate, 0, BatchSize),
		Chains: make([][]*ctx509.Certificate, 0, BatchSize),
		cns:    make([]*string, 0, BatchSize),
	}
}

// AddData pushed the cert data into the batch.
func (b *Batch) AddData(d *CertData) {
	b.Certs = append(b.Certs, d.Cert)
	b.Chains = append(b.Chains, d.CertChain)
	b.cns = append(b.cns, &d.Cert.Subject.CommonName)
}

func (b *Batch) Full() bool {
	return len(b.Certs) == BatchSize
}

type BatchProcessor struct {
	conn db.Conn

	incomingCh chan *Batch
	incomingWg sync.WaitGroup
	doneCh     chan struct{}

	runningBatches   map[string]*Batch
	runningBatchesMu sync.Mutex
	reschedules      atomic.Int64
}

func NewBatchProcessor(conn db.Conn) *BatchProcessor {
	p := &BatchProcessor{
		conn:       conn,
		incomingCh: make(chan *Batch),
		doneCh:     make(chan struct{}),

		runningBatches: make(map[string]*Batch),
	}
	p.start()
	return p
}

func (p *BatchProcessor) start() {
	go func() {
		for batch := range p.incomingCh {
			go p.wrapBatch(batch)
		}
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
	fmt.Printf("# reschedules: %d\n", p.reschedules.Load())
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
	if err := p.checkIfBatchClashes(batch); err != nil {
		// At least one name in this batch is already being processed at a different batch,
		// and we can't use different batches that contain a non nil intersection.
		// Just reschedule the batch in the hopes that it will eventually picked up when
		// the active batches don't clash with it:
		p.reschedules.Add(1)
		p.incomingCh <- batch
		return
	}

	p.addBatchAsActive(batch)
	defer p.removeBatchFromActive(batch)
	defer p.incomingWg.Done() // one less batch to process

	p.processBatch(batch)
}

func (p *BatchProcessor) processBatch(batch *Batch) {
	affectedDomainsMap, domainCertMap, domainCertChainMap :=
		updater.GetAffectedDomainAndCertMap(batch.Certs, batch.Chains)
	if len(affectedDomainsMap) == 0 {
		return
	}
	_ = affectedDomainsMap
	_ = domainCertMap
	_ = domainCertChainMap
	// TODO(juagargi) do the actual update
}

func (p *BatchProcessor) checkIfBatchClashes(b *Batch) error {
	p.runningBatchesMu.Lock()
	defer p.runningBatchesMu.Unlock()

	for _, cn := range b.cns {
		if other, ok := p.runningBatches[*cn]; ok && other != b {
			return fmt.Errorf("same CN in different batches, pointers: %p, %p. CN: %s",
				other, b.cns, *cn)
		}
	}
	return nil
}

func (p *BatchProcessor) addBatchAsActive(b *Batch) {
	p.runningBatchesMu.Lock()
	defer p.runningBatchesMu.Unlock()

	for _, cn := range b.cns {
		p.runningBatches[*cn] = b
	}
}

func (p *BatchProcessor) removeBatchFromActive(b *Batch) {
	p.runningBatchesMu.Lock()
	defer p.runningBatchesMu.Unlock()

	for _, cn := range b.cns {
		delete(p.runningBatches, *cn)
	}
}
