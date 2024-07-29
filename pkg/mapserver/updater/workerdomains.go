package updater

import (
	"context"
	"fmt"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	pip "github.com/netsec-ethz/fpki/pkg/pipeline"
	"github.com/netsec-ethz/fpki/pkg/util"
)

type DomainWorker struct {
	baseWorker
	pip.Sink[DirtyDomain]

	Domains []DirtyDomain // Created once, reused.

	domainIDs []common.SHA256Output // do not call make more than once.
	certIDs   []common.SHA256Output // do not call make more than once.
	names     []string              // do not call make more than once.

	cloneDomainIDs []common.SHA256Output // to avoid calling malloc when we run dedup.
	cloneCertIDs   []common.SHA256Output // to avoid calling malloc when we run dedup.
	cloneNames     []string              // to avoid calling malloc when we run dedup.

	dedupIDStorage     map[common.SHA256Output]struct{}    // For dedup to not allocate.
	dedupIdNameStorage map[idName]struct{}                 // For dedup to not allocate.
	dedupTwoIdsStorage map[[2]common.SHA256Output]struct{} // For dedup to not allocate.
}

func NewDomainWorker(
	ctx context.Context,
	id int,
	m *Manager,
	conn db.Conn,
	workerCount int,
) *DomainWorker {
	w := &DomainWorker{
		baseWorker: *newBaseWorker(ctx, id, m, conn),

		// Create a certificate slice where all the received certificates will end up.
		Domains: make([]DirtyDomain, 0, m.MultiInsertSize),

		domainIDs: make([]common.SHA256Output, 0, m.MultiInsertSize),
		certIDs:   make([]common.SHA256Output, 0, m.MultiInsertSize),
		names:     make([]string, 0, m.MultiInsertSize),

		cloneDomainIDs: make([]common.SHA256Output, 0, m.MultiInsertSize),
		cloneCertIDs:   make([]common.SHA256Output, 0, m.MultiInsertSize),
		cloneNames:     make([]string, 0, m.MultiInsertSize),

		dedupIDStorage:     make(map[common.SHA256Output]struct{}, 2*m.MultiInsertSize),
		dedupIdNameStorage: make(map[idName]struct{}, m.MultiInsertSize),
		dedupTwoIdsStorage: make(map[[2]common.SHA256Output]struct{}, m.MultiInsertSize),
	}

	// Each domain worker needs N channels, one per cert worker, where they receive the domain
	// from that specific cert worker. When the cert worker is done, it will close only that
	// specific channel.
	w.Sink = *pip.NewSink(
		fmt.Sprintf("domain_worker_%2d", id),
		pip.WithSinkFunction(
			func(domain DirtyDomain) error {
				var err error
				w.Domains = append(w.Domains, domain)
				// Only if we have filled a complete bundle, process.
				if len(w.Domains) == m.MultiInsertSize {
					err = w.processBundle(w.Domains)
					// Continue reading certificates until incomingChan is closed.
					w.Domains = w.Domains[:0] // Reuse storage, but reset elements
				}
				return err
			},
		),
		pip.WithMultiInputChannels[DirtyDomain, pip.None](workerCount),
		pip.WithOnNoMoreData[DirtyDomain, pip.None](
			func() ([]pip.None, []int, error) {
				// Process the last (possibly empty) batch.
				err := w.processBundle(w.Domains)
				w.Domains = w.Domains[:0]
				return nil, nil, err
			},
		),
	)

	return w
}

func (w *DomainWorker) processBundle(domains []DirtyDomain) error {
	if len(domains) == 0 {
		return nil
	}

	w.domainIDs = w.domainIDs[:len(domains)] // keep storage
	w.certIDs = w.certIDs[:len(domains)]
	w.names = w.names[:len(domains)]
	for i, d := range domains {
		w.domainIDs[i] = d.DomainID
		w.names[i] = d.Name
		w.certIDs[i] = d.CertID
	}

	// Remove duplicates for the dirty table insertion.
	w.cloneDomainIDs = append(w.cloneDomainIDs[:0], w.domainIDs...)
	util.DeduplicateSliceWithStorage(
		w.dedupIDStorage,
		util.WithSlice(w.cloneDomainIDs),
		util.Wrap(&w.cloneDomainIDs),
	)

	// Update dirty table.
	if err := w.Conn.InsertDomainsIntoDirty(w.Ctx, w.cloneDomainIDs); err != nil {
		return fmt.Errorf("inserting domains at worker %d: %w", w.Id, err)
	}

	// Remove duplicates (domainID,name)
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

	// Update domains table.
	if err := w.Conn.UpdateDomains(w.Ctx, w.cloneDomainIDs, w.cloneNames); err != nil {
		return fmt.Errorf("inserting domains at worker %d: %w", w.Id, err)
	}

	// Update domain_certs.
	// Remove duplicates (domainID, certID)
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
	if err := w.Conn.UpdateDomainCerts(w.Ctx, w.cloneDomainIDs, w.cloneCertIDs); err != nil {
		return fmt.Errorf("inserting domains at worker %d: %w", w.Id, err)
	}

	return nil
}

// idName is the bundle of the ID and name, to deduplicate domainID,name insertion.
type idName struct {
	id   common.SHA256Output
	name string
}
