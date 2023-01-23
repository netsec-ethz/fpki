package main

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	mcommon "github.com/netsec-ethz/fpki/pkg/mapserver/common"
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
	fmt.Println("batch processed")
}

func (p *BatchProcessor) processBatch(batch *Batch) {
	// Compute which domains could be affected:
	affectedDomainsMap, domainCertMap, domainCertChainMap := updater.GetAffectedDomainAndCertMap(
		batch.Certs, batch.Chains)
	if len(affectedDomainsMap) == 0 {
		return
	}

	// Get all affected entries already present in the DB:
	affectedDomainHashes := make([]common.SHA256Output, 0, len(affectedDomainsMap))
	for k := range affectedDomainsMap {
		affectedDomainHashes = append(affectedDomainHashes, k)
	}
	domainEntries, err := p.conn.RetrieveDomainEntries(context.Background(), affectedDomainHashes)
	if err != nil {
		panic(err)
	}

	// Obtain a map from SHAs to certificates:
	shaToCerts := make(map[common.SHA256Output]*mcommon.DomainEntry)
	for _, kv := range domainEntries {
		entry, err := mcommon.DeserializeDomainEntry(kv.Value)
		if err != nil {
			panic(err)
		}
		shaToCerts[kv.Key] = entry
	}

	// Update Domain Entries in DB:
	updatedDomains, err := updater.UpdateDomainEntries(shaToCerts, domainCertMap, domainCertChainMap)
	if err != nil {
		panic(err)
	}
	shaToCerts, err = updater.GetDomainEntriesToWrite(updatedDomains, shaToCerts)
	if err != nil {
		panic(err)
	}
	domainEntries, err = updater.SerializeUpdatedDomainEntries(shaToCerts)
	if err != nil {
		panic(err)
	}
	_, err = p.conn.UpdateDomainEntries(context.Background(), domainEntries)
	if err != nil {
		panic(err)
	}

	inputKeys, inputValues, err := updater.KeyValuePairToSMTInput(domainEntries)
	if err != nil {
		panic(err)
	}
	// TODO(juagargi) update SMT with the above
	_ = inputKeys
	_ = inputValues
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
