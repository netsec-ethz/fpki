package main

import (
	"fmt"
	"sync"

	"github.com/netsec-ethz/fpki/pkg/db"
)

const BatchSize = 10000

type Batch struct {
	data []*CertData
	cns  []*string
}

func NewBatch() *Batch {
	return &Batch{
		data: make([]*CertData, 0, BatchSize),
		cns:  make([]*string, 0, BatchSize),
	}
}

// AddData pushed the cert data into the batch.
func (b *Batch) AddData(d *CertData) {
	b.data = append(b.data, d)
	b.cns = append(b.cns, &d.Cert.Subject.CommonName)
}

func (b *Batch) Full() bool {
	return len(b.data) == BatchSize
}

type BatchProcessor struct {
	conn       db.Conn
	incomingCh chan *Batch
	// finishedCh chan *Batch

	runningBatches   map[string]*Batch
	runningBatchesMu sync.Mutex
}

func NewBatchProcessor(conn db.Conn) *BatchProcessor {
	p := &BatchProcessor{
		conn:       conn,
		incomingCh: make(chan *Batch),

		runningBatches:   make(map[string]*Batch),
		runningBatchesMu: sync.Mutex{},
	}
	p.start()
	return p
}

func (p *BatchProcessor) start() {
	go func() {
		for batch := range p.incomingCh {
			go p.processBatch(batch)
		}
	}()
}

// Process processes a Batch into the DB.
func (p *BatchProcessor) Process(b *Batch) {
	p.incomingCh <- b
}

func (p *BatchProcessor) processBatch(b *Batch) {
	if err := p.checkIfBatchClashes(b); err != nil {
		panic(err)
	}
	p.addBatchAsActive(b)
	// TODO(juagargi) do the actual update
	p.removeBatchFromActive(b)
}

func (p *BatchProcessor) checkIfBatchClashes(b *Batch) error {
	p.runningBatchesMu.Lock()
	defer p.runningBatchesMu.Unlock()

	for _, cn := range b.cns {
		if other, ok := p.runningBatches[*cn]; ok && other != b {
			return fmt.Errorf("same CN in different batches")
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
