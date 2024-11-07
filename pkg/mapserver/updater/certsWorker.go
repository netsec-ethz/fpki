package updater

import (
	"fmt"
	"time"

	"github.com/netsec-ethz/fpki/pkg/cache"
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	pip "github.com/netsec-ethz/fpki/pkg/pipeline"
	tr "github.com/netsec-ethz/fpki/pkg/tracing"
	"github.com/netsec-ethz/fpki/pkg/util"
)

// The certificate workers stages receive Certificate as input, and:
// - Batches the certificates in a slice to be inserted in the DB.
// - For each certificate, it extracts domains and output them to the next stage.
//
// For this purpose we have the following stages:
// 1. The source must send the same certificate to stages 2 and 3 below.
// 2. Gets a certificate and batches them. It outputs a batch for stage 4
// 3. Gets a certificate and obtains its domains and sends them to the next stages (domain batchers)
// 4. Gets a certificate batch and inserts it into the DB.
//
// All stages need only one input channel. The types for each stage are:
// 2. certBatcher			Outputs to one certInserter
// 3. domainExtractor		Outputs to N domain batchers.
// 4. certInserter			Sinks.

// CertBatch is a slice of certificates.
type CertBatch []Certificate

// certBatcher receives one certificate and outputs one batch.
type certBatcher struct {
	*pip.Stage[Certificate, CertBatch]
	certs ringCache[Certificate] // Created once, reused.
}

func newCertBatcher(
	id int,
	m *Manager,
) *certBatcher {
	// Create the batcher with its storage.
	w := &certBatcher{
		certs: newRingCache[Certificate](m.MultiInsertSize),
	}

	batchSlice := make([]CertBatch, 1)
	outChannels := []int{0}
	w.Stage = pip.NewStage[Certificate, CertBatch](
		fmt.Sprintf("cert_batcher_%02d", id),
		pip.WithProcessFunction(func(in Certificate) ([]CertBatch, []int, error) {
			w.certs.addElem(in)
			if w.certs.currLength() == m.MultiInsertSize {
				_, span := w.Tracer.Start(w.Ctx, "sending-batch")
				defer span.End()

				batchSlice[0] = w.certs.current()
				w.certs.rotate()
				return batchSlice, outChannels, nil
			}
			return nil, nil, nil
		}),
		pip.WithOnNoMoreData[Certificate, CertBatch](func() ([]CertBatch, []int, error) {
			batchSlice[0] = w.certs.current()
			w.certs.rotate()
			return batchSlice, outChannels, nil
		}),
	)

	return w
}

// domainExtractor receives one certificate and outputs to N domain batchers.
type domainExtractor struct {
	*pip.Stage[Certificate, DirtyDomain]
	hasher        common.Hasher
	domains       ringCache[DirtyDomain] // Keep a copy until the next stage has finished.
	domainIdCache cache.Cache            // Keep track of the already seen domains.
}

func newDomainExtractor(
	id int,
	m *Manager,
	workerCount int,
	domainIdCache cache.Cache,
) *domainExtractor {
	// Create the domain extractor, with one domains storage, that keeps two slices of domains.
	// These two slices have been preallocated already, and its storage is being reused.
	w := &domainExtractor{
		hasher:        *common.NewHasher(),
		domainIdCache: domainIdCache,
		domains:       newRingCache[DirtyDomain](10), // Preallocate 10 domains per cert.
	}
	outChannels := make([]int, 0, 10)

	w.Stage = pip.NewStage[Certificate, DirtyDomain](
		fmt.Sprintf("domain_extractor_%02d", id),
		pip.WithMultiOutputChannels[Certificate, DirtyDomain](workerCount),
		pip.WithProcessFunction(func(in Certificate) ([]DirtyDomain, []int, error) {
			outChannels = outChannels[:0] // reuse index slice.
			w.domains.rotate()
			for _, name := range in.Names {
				id := w.hasher.HashStringCopy(name)
				if !w.domainIdCache.Contains(&id) {
					// Add it to the cache.
					w.domainIdCache.AddIDs(&id)

					// Send it to next stages.
					d := DirtyDomain{
						DomainID: id,
						CertID:   in.CertID,
						Name:     name,
					}
					w.domains.addElem(d)
					outChannels = append(
						outChannels,
						int(m.ShardFuncDomain(&d.DomainID)),
					)
				}
			}
			return w.domains.current(), outChannels, nil
		}),
	)

	return w
}

// certInserter receives one certBatch and inserts it into the DB. It is a sink.
// deleteme: this stage should actually be more than one: writing the CSVs, updating tables.
type certInserter struct {
	*pip.Sink[CertBatch]
	// Cache storage arrays used to unfold Certificate objects into the DB fields.
	cacheIds         []common.SHA256Output
	cacheParents     []*common.SHA256Output
	cacheExpirations []time.Time
	cachePayloads    [][]byte

	dedupStorage map[common.SHA256Output]struct{} // For dedup to not allocate.
}

func newCertInserter(
	id int,
	m *Manager,
) *certInserter {
	w := &certInserter{
		cacheIds:         make([]common.SHA256Output, 0, m.MultiInsertSize),
		cacheParents:     make([]*common.SHA256Output, 0, m.MultiInsertSize),
		cacheExpirations: make([]time.Time, 0, m.MultiInsertSize),
		cachePayloads:    make([][]byte, 0, m.MultiInsertSize),

		dedupStorage: make(map[common.SHA256Output]struct{}, m.MultiInsertSize),
	}

	w.Sink = pip.NewSink[CertBatch](
		fmt.Sprintf("cert_inserter_%02d", id),
		pip.WithSinkFunction(func(batch CertBatch) error {
			return w.insertCertificates(m.Conn, batch)
		}),
	)

	return w
}

func (w *certInserter) insertCertificates(conn db.Conn, batch CertBatch) error {
	ctx, span := w.Tracer.Start(w.Ctx, "process-batch")
	defer span.End()
	tr.SetAttrInt(span, "num-domains", len(batch))

	// Reuse storage for the data translation.
	w.cacheIds = w.cacheIds[:len(batch)]
	w.cacheParents = w.cacheParents[:len(batch)]
	w.cacheExpirations = w.cacheExpirations[:len(batch)]
	w.cachePayloads = w.cachePayloads[:len(batch)]

	{
		// Flatten data structure.
		_, span := w.Tracer.Start(ctx, "flatten")

		for i, c := range batch {
			w.cacheIds[i] = c.CertID
			w.cacheParents[i] = c.ParentID
			w.cacheExpirations[i] = c.Cert.NotAfter
			w.cachePayloads[i] = c.Cert.Raw
		}

		span.End()
	}
	{
		// Remove duplicates for the dirty table insertion.
		_, span := w.Tracer.Start(ctx, "dedup-certs")

		// Remove duplicated certs.
		util.DeduplicateSliceWithStorage(
			w.dedupStorage,
			func(i int) common.SHA256Output {
				return w.cacheIds[i]
			},
			util.Wrap(&w.cacheIds),
			util.Wrap(&w.cacheParents),
			util.Wrap(&w.cacheExpirations),
			util.Wrap(&w.cachePayloads),
		)

		span.End()
	}
	{
		_, span := w.Tracer.Start(ctx, "update-certs")

		err := conn.UpdateCerts(
			ctx,
			w.cacheIds,
			w.cacheParents,
			w.cacheExpirations,
			w.cachePayloads,
		)

		span.End()
		return err
	}
}
