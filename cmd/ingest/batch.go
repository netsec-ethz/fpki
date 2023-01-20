package main

const BatchSize = 10000

type Batch struct {
	data []*CertData
}

func NewBatch() *Batch {
	return &Batch{
		data: make([]*CertData, 0, BatchSize),
	}
}

// AddData pushed the cert data into the batch.
func (b *Batch) AddData(d *CertData) {
	b.data = append(b.data, d)
}

func (b *Batch) Full() bool {
	return len(b.data) == BatchSize
}
