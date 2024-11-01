package updater

import (
	"fmt"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	pip "github.com/netsec-ethz/fpki/pkg/pipeline"
	tr "github.com/netsec-ethz/fpki/pkg/tracing"
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

type domainInserter struct {
	baseWorker
	*pip.Sink[domainBatch]

	domainIDs []common.SHA256Output // do not call make more than once.
	certIDs   []common.SHA256Output // do not call make more than once.
	names     []string              // do not call make more than once.

	cloneDomainIDs []common.SHA256Output // to avoid calling malloc when we run dedup.
	cloneNames     []string              // to avoid calling malloc when we run dedup.
	cloneCertIDs   []common.SHA256Output // to avoid calling malloc when we run dedup.

	dedupIDStorage     map[common.SHA256Output]struct{}    // For dedup to not allocate.
	dedupIdNameStorage map[idName]struct{}                 // For dedup to not allocate.
	dedupTwoIdsStorage map[[2]common.SHA256Output]struct{} // For dedup to not allocate.
}

func newDomainInserter(
	id int,
	m *Manager,
) *domainInserter {
	w := &domainInserter{
		baseWorker: *newBaseWorker(m),

		domainIDs: make([]common.SHA256Output, 0, m.MultiInsertSize),
		certIDs:   make([]common.SHA256Output, 0, m.MultiInsertSize),
		names:     make([]string, 0, m.MultiInsertSize),

		cloneDomainIDs: make([]common.SHA256Output, 0, m.MultiInsertSize),
		cloneNames:     make([]string, 0, m.MultiInsertSize),
		cloneCertIDs:   make([]common.SHA256Output, 0, m.MultiInsertSize),

		dedupIDStorage:     make(map[common.SHA256Output]struct{}, 2*m.MultiInsertSize),
		dedupIdNameStorage: make(map[idName]struct{}, m.MultiInsertSize),
		dedupTwoIdsStorage: make(map[[2]common.SHA256Output]struct{}, m.MultiInsertSize),
	}

	w.Sink = pip.NewSink[domainBatch](
		fmt.Sprintf("domain_inserter_%02d", id),
		pip.WithSinkFunction(
			func(batch domainBatch) error {
				return w.processBatch(batch)
			},
		),
	)

	return w
}

func (w domainInserter) conn() db.Conn {
	return w.Manager.Conn
}

func (w *domainInserter) processBatch(batch []DirtyDomain) error {
	ctx, span := w.Tracer.Start(w.Ctx, "process-batch")
	defer span.End()
	tr.SetAttrInt(span, "num-domains", len(batch))

	if len(batch) == 0 {
		return nil
	}

	{
		// Flatten data structure.
		_, span := w.Tracer.Start(ctx, "flatten")

		// keep storage
		w.domainIDs = w.domainIDs[:len(batch)]
		w.certIDs = w.certIDs[:len(batch)]
		w.names = w.names[:len(batch)]
		for i, d := range batch {
			w.domainIDs[i] = d.DomainID
			w.names[i] = d.Name
			w.certIDs[i] = d.CertID
		}

		span.End()
	}
	{
		// Remove duplicates for the dirty table insertion.
		_, span := w.Tracer.Start(ctx, "dedup-dirty")

		w.cloneDomainIDs = append(w.cloneDomainIDs[:0], w.domainIDs...)
		util.DeduplicateSliceWithStorage(
			w.dedupIDStorage,
			util.WithSlice(w.cloneDomainIDs),
			util.Wrap(&w.cloneDomainIDs),
		)

		span.End()
	}
	{
		// Update dirty table.
		_, span := w.Tracer.Start(ctx, "insert-dirty")

		if err := w.conn().InsertDomainsIntoDirty(ctx, w.cloneDomainIDs); err != nil {
			return fmt.Errorf("inserting domains at worker %s: %w", w.Name, err)
		}

		span.End()
	}
	{
		// Remove duplicates (domainID,name)
		_, span := w.Tracer.Start(ctx, "dedup-domain-names")
		tr.SetAttrInt(span, "num-original", len(w.domainIDs))

		w.cloneDomainIDs = append(w.cloneDomainIDs[:0], w.domainIDs...) // clone again (was modified).
		w.cloneNames = append(w.cloneNames[:0], w.names...)

		util.DeduplicateSliceWithStorage(
			w.dedupIdNameStorage,
			func(i int) idName {
				return idName{
					id:   w.cloneDomainIDs[i],
					name: w.cloneNames[i],
				}
			},
			util.Wrap(&w.cloneDomainIDs),
			util.Wrap(&w.cloneNames),
		)

		// After deduplication.
		tr.SetAttrInt(span, "num-deduplicated", len(w.cloneDomainIDs))
		span.End()
	}
	{
		// Update domains table.
		_, span := w.Tracer.Start(ctx, "insert-domains")
		tr.SetAttrInt(span, "num", len(w.cloneDomainIDs))

		if err := w.conn().UpdateDomains(ctx, w.cloneDomainIDs, w.cloneNames); err != nil {
			err := fmt.Errorf("inserting domains at worker %s: %w", w.Name, err)
			span.RecordError(err)
			span.End()
			return err
		}

		span.End()
	}
	// Update domain_certs.
	{
		// Remove duplicates (domainID, certID)
		_, span := w.Tracer.Start(ctx, "dedup-domain-certs")
		tr.SetAttrInt(span, "num-original", len(w.domainIDs))

		w.cloneDomainIDs = append(w.cloneDomainIDs[:0], w.domainIDs...) // again
		w.cloneCertIDs = append(w.certIDs[:0], w.certIDs...)
		util.DeduplicateSliceWithStorage(
			w.dedupTwoIdsStorage,
			func(i int) [2]common.SHA256Output {
				return [2]common.SHA256Output{
					w.cloneDomainIDs[i],
					w.cloneCertIDs[i],
				}
			},
			util.Wrap(&w.cloneDomainIDs),
			util.Wrap(&w.cloneCertIDs),
		)
		// After deduplication.
		tr.SetAttrInt(span, "num-deduplicated", len(w.cloneDomainIDs))
		span.End()
	}
	{
		// Update domain_certs table.
		_, span := w.Tracer.Start(ctx, "insert-domain-certs")
		tr.SetAttrInt(span, "num", len(w.cloneCertIDs))

		if err := w.conn().UpdateDomainCerts(ctx, w.cloneDomainIDs, w.cloneCertIDs); err != nil {
			err := fmt.Errorf("inserting domains at worker %s: %w", w.Name, err)
			span.RecordError(err)
			span.End()
			return err
		}

		span.End()
	}

	return nil
}

// idName is the bundle of the ID and name, to deduplicate domainID,name insertion.
type idName struct {
	id   common.SHA256Output
	name string
}
