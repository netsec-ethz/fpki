package updater

import (
	"fmt"
	"os"

	pip "github.com/netsec-ethz/fpki/pkg/pipeline"
	"github.com/netsec-ethz/fpki/pkg/util"
)

// The domain workers comprise two types of Stages:
// 1. Cache domains into a bundle.
// 2. Process and store the bundle.
//
// The two stages are necessary to not block the whole pipeline while the stage number 2 is running,
// as it requires some milliseconds to finish. While stage 2 is running, stage 1 will still accept
// incoming domains.

type domainBatch []DirtyDomain

type domainBatcher struct {
	*pip.Stage[DirtyDomain, domainBatch]
	domains        ringCache[DirtyDomain] // Created once, reused.
	outputChannels []int                  // Created once, reused.
}

func newDomainBatcher(
	id int,
	m *Manager,
	workerCount int,
) *domainBatcher {
	// First create the domain batcher with its caches.
	w := &domainBatcher{
		domains:        newRingCache[DirtyDomain](m.MultiInsertSize),
		outputChannels: make([]int, m.MultiInsertSize),
	}
	// Allocate a slice of domainBatch and reuse it to send the output.
	domainBatchWrap := make([]domainBatch, 1)

	// Prepare the pipeline stage.
	w.Stage = pip.NewStage[DirtyDomain, domainBatch](
		fmt.Sprintf("domain_batcher_%02d", id),
		// Each domain worker needs N channels, one per cert worker, where they receive the domain
		// from that specific cert worker. When the cert worker is done, it will close only that
		// specific channel.
		pip.WithMultiInputChannels[DirtyDomain, domainBatch](workerCount),
		pip.WithProcessFunction(func(in DirtyDomain) ([]domainBatch, []int, error) {
			w.domains.addElem(in)
			if w.domains.currLength() == m.MultiInsertSize {
				_, span := w.Tracer.Start(w.Ctx, "batch-created")
				defer span.End()

				domainBatchWrap[0] = w.domains.current()
				w.domains.rotate()
				return domainBatchWrap, w.outputChannels, nil
			}
			return nil, nil, nil
		}),
		pip.WithOnNoMoreData[DirtyDomain, domainBatch](func() ([]domainBatch, []int, error) {
			// Send the last (possibly empty) batch.
			if l := w.domains.currLength(); l > 0 {
				domainBatchWrap[0] = w.domains.current()
				w.domains.rotate()
				return domainBatchWrap, w.outputChannels[:l], nil
			}
			return nil, nil, nil
		}),
	)

	return w
}

type domainsCsvFilenames struct {
	dirtyFile       string
	domainsFile     string
	domainCertsFile string
}

type domainsToCsvs struct {
	*pip.Stage[domainBatch, domainsCsvFilenames]
}

func newDomainsToCsvs(
	id int,
	m *Manager,
) *domainsToCsvs {
	w := &domainsToCsvs{}

	// Prepare pre-reserved storage for the strings.
	storageDirty := CreateStorage(m.MultiInsertSize, 1,
		IdBase64Len,
	)
	storageDomains := CreateStorage(m.MultiInsertSize, 2,
		IdBase64Len,
		DomainNameLen,
	)
	storageDomainCerts := CreateStorage(m.MultiInsertSize, 2,
		IdBase64Len,
		IdBase64Len,
	)

	filenameSlice := make([]domainsCsvFilenames, 1)
	outChs := make([]int, 1)
	var err error
	w.Stage = pip.NewStage[domainBatch, domainsCsvFilenames](
		fmt.Sprintf("domain_batch_to_csv_%02d", id),
		pip.WithProcessFunction(func(batch domainBatch) ([]domainsCsvFilenames, []int, error) {
			_, span := w.Tracer.Start(w.Ctx, "create-csvs")
			defer span.End()

			if len(batch) == 0 {
				return nil, nil, nil
			}

			filenameSlice[0].dirtyFile, err = CreateCsvDirty(storageDirty, batch)
			if err != nil {
				return nil, nil, err
			}
			filenameSlice[0].domainsFile, err = CreateCsvDomains(storageDomains, batch)
			if err != nil {
				return nil, nil, err
			}
			filenameSlice[0].domainCertsFile, err = CreateCsvDomainCerts(storageDomainCerts, batch)

			return filenameSlice, outChs, err
		}),
	)

	return w
}

type domainCsvsInserter struct {
	*pip.Stage[domainsCsvFilenames, domainsCsvFilenames]
}

func newDomainCsvsInserter(id int, m *Manager) *domainCsvsInserter {
	w := &domainCsvsInserter{}

	filenameSlice := make([]domainsCsvFilenames, 1)
	outChs := make([]int, 1)
	var err error

	w.Stage = pip.NewStage[domainsCsvFilenames, domainsCsvFilenames](
		fmt.Sprintf("domain_csv_inserter_%02d", id),
		pip.WithProcessFunction(func(in domainsCsvFilenames) ([]domainsCsvFilenames, []int, error) {
			ctx, span := w.Tracer.Start(w.Ctx, "csv-to-db")
			defer span.End()

			// Call the db to insert.
			filenameSlice[0] = in
			err = m.Conn.InsertCsvIntoDirty(ctx, in.dirtyFile)
			if err != nil {
				return nil, nil, err
			}
			err = m.Conn.InsertCsvIntoDomains(ctx, in.domainsFile)
			if err != nil {
				return nil, nil, err
			}
			err = m.Conn.InsertCsvIntoDomainCerts(ctx, in.domainCertsFile)
			return filenameSlice, outChs, err
		}),
	)

	return w
}

type domainCsvsRemover struct {
	*pip.Sink[domainsCsvFilenames]
}

func newDomainCsvsRemover(id int) *domainCsvsRemover {
	errs := make([]error, 3)
	return &domainCsvsRemover{
		Sink: pip.NewSink[domainsCsvFilenames](
			fmt.Sprintf("domain_csvs_remover_%02d", id),
			pip.WithSinkFunction(func(in domainsCsvFilenames) error {
				errs[0] = os.Remove(in.dirtyFile)
				errs[1] = os.Remove(in.domainsFile)
				errs[2] = os.Remove(in.domainCertsFile)
				return util.ErrorsCoalesce(errs...)
			}),
		),
	}
}
