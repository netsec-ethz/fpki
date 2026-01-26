package updater

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/netsec-ethz/fpki/pkg/cache"
	"github.com/netsec-ethz/fpki/pkg/common"
	pip "github.com/netsec-ethz/fpki/pkg/pipeline"
)

// The certificate workers stages receive Certificate as input, and:
// - Batches the certificates in a slice to be inserted in the DB.
// - For each certificate, it extracts domains and output them to the next stage.
//
// For this purpose we have the following stages:
// 1. The source must send the same certificate to stages 2 and 3 below.
// 2. Gets a certificate and batches them. It outputs a batch for stage 4.
// 3. Gets a certificate and obtains its domains and sends them to the next domain batcher stages.
// 4. Gets a certificate batch and creates a CSV file. Outputs a filename for stage 5.
// 5. Gets a CSV file and inserts it into the DB. Outputs a filename for stage 6.
// 6. Removes the CSV file.
//
// All stages need only one input channel. The types for each stage are:
// 2. certBatcher			Outputs to one certBatchToCsv
// 3. domainExtractor		Outputs to N domain batchers.
// 4. certBatchToCsv		Outputs to 1 certCsvInserter.
// 5. certCsvInserter		Outputs to 1 certCsvRemover.
// 6. certCsvRemover		Sinks.

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
			// deleteme
			shard := m.ShardFuncCert((*common.SHA256Output)(&in.CertID))
			if int(shard) != id {
				panic(fmt.Errorf("B: the computed shard %d is different than the expected %d for %s",
					shard, id, hex.EncodeToString(in.CertID[:])))
			}
			// end of deleteme
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
	id            int
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
		id:            id,
	}
	outChannels := make([]int, 0, 10)

	w.Stage = pip.NewStage[Certificate, DirtyDomain](
		fmt.Sprintf("domain_extractor_%02d", id),
		pip.WithMultiOutputChannels[Certificate, DirtyDomain](workerCount),
		pip.WithProcessFunction(func(in Certificate) ([]DirtyDomain, []int, error) {
			// deleteme
			wtf := in.CertID[:]
			shard := m.ShardFuncCert((*common.SHA256Output)(&in.CertID))
			if int(shard) != id {
				panic(fmt.Errorf("C: the computed shard %d is different than the expected "+
					"%d for %s; cert shard = %d {wtf: %s}",
					shard, id, hex.EncodeToString(in.CertID[:]), in.DeletemeShard, hex.EncodeToString(wtf)))
				return nil, nil, nil
			}
			// end of deleteme
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

// certBatchToCsv receives one certBatch and creates a CSV file.
type certBatchToCsv struct {
	*pip.Stage[CertBatch, string]
}

func newCertBatchToCsv(
	id int,
	m *Manager,
) *certBatchToCsv {
	w := &certBatchToCsv{}

	// Prepare pre-reserved storage for the strings.
	storage := CreateStorage(m.MultiInsertSize, 4,
		IdBase64Len,
		IdBase64Len,
		ExpTimeBase64Len,
		PayloadBase64Len,
	)
	// Storage to keep the different temporary file names per call to the process function.
	filenamesStorage := createFilepathRingCache()

	filenameSlice := make([]string, 1) // holds the slice (not the storage) of the temp file.
	outChs := make([]int, 1)
	var err error
	w.Stage = pip.NewStage[CertBatch, string](
		fmt.Sprintf("cert_batch_to_csv_%02d", id),
		pip.WithProcessFunction(func(batch CertBatch) ([]string, []int, error) {
			_, span := w.Tracer.Start(w.Ctx, "create-csv")
			defer span.End()

			filenameSlice[0], err = CreateCsvCerts(storage, filenamesStorage.Rotate(), batch)
			return filenameSlice, outChs, err
		}),
	)

	return w
}

type certCsvInserter struct {
	*pip.Stage[string, string]
}

func newCertCsvInserter(id int, m *Manager) *certCsvInserter {
	w := &certCsvInserter{}

	filenameSlice := make([]string, 1)
	outChs := make([]int, 1)
	var err error

	w.Stage = pip.NewStage[string, string](
		fmt.Sprintf("cert_csv_inserter_%02d", id),
		pip.WithProcessFunction(func(in string) ([]string, []int, error) {
			ctx, span := w.Tracer.Start(w.Ctx, "csv-to-db")
			defer span.End()

			// Call the db to insert.
			filenameSlice[0] = in
			err = m.Conn.InsertCsvIntoCerts(ctx, in)
			_ = ctx
			return filenameSlice, outChs, err
		}),
	)
	return w
}

type certCsvRemover struct {
	*pip.Sink[string]
}

func newCertCsvRemover(id int) *certCsvRemover {
	return &certCsvRemover{
		Sink: pip.NewSink[string](
			fmt.Sprintf("cert_csv_remover_%02d", id),
			pip.WithSinkFunction(func(in string) error {
				// deleteme
				return nil
				return os.Remove(in)
			}),
		),
	}
}
