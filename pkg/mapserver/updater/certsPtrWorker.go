package updater

import (
	"context"
	"fmt"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	pip "github.com/netsec-ethz/fpki/pkg/pipeline"
	"github.com/netsec-ethz/fpki/pkg/util"
)

type CertPtrWorker struct {
	baseWorker
	*pip.Stage[*Certificate, *DirtyDomain]
	hasher common.Hasher

	Certs  []*Certificate // Created once, reused.
	outChs []int          // Reuse the out channel indices slice.

	// Cache storage arrays used to unfold Certificate objects into the DB fields.
	cacheIds         []common.SHA256Output
	cacheParents     []*common.SHA256Output
	cacheExpirations []time.Time
	cachePayloads    [][]byte

	dedupStorage map[common.SHA256Output]struct{} // For dedup to not allocate.
}

func NewCertPtrWorker(
	ctx context.Context,
	id int,
	m *Manager,
	conn db.Conn,
	workerCount int,
) *CertPtrWorker {
	w := &CertPtrWorker{
		baseWorker: *newBaseWorker(ctx, id, m, conn),
		hasher:     *common.NewHasher(),

		Certs:  make([]*Certificate, 0, m.MultiInsertSize),
		outChs: make([]int, 0, m.MultiInsertSize*3), // Initial storage is 3 domains per cert.

		cacheIds:         make([]common.SHA256Output, 0, m.MultiInsertSize),
		cacheParents:     make([]*common.SHA256Output, 0, m.MultiInsertSize),
		cacheExpirations: make([]time.Time, 0, m.MultiInsertSize),
		cachePayloads:    make([][]byte, 0, m.MultiInsertSize),

		dedupStorage: make(map[common.SHA256Output]struct{}, m.MultiInsertSize),
	}
	name := fmt.Sprintf("cert_worker_%02d", id)
	w.Stage = pip.NewStage[*Certificate, *DirtyDomain](
		name,
		pip.WithMultiOutputChannels[*Certificate, *DirtyDomain](workerCount),
		// pip.WithSequentialOutputs[*Certificate, *DirtyDomain](),
		// pip.WithSequentialInputs[*Certificate, *DirtyDomain](),
		pip.WithProcessFunction(
			func(cert *Certificate) ([]*DirtyDomain, []int, error) {
				w.Certs = append(w.Certs, cert)
				// Only if we have filled a complete bundle, process.
				if pip.DebugEnabled {
					pip.DebugPrintf("[%s] worker got cert %s, batch size: %d \n", name, cert, len(w.Certs))
				}
				if len(w.Certs) == m.MultiInsertSize {
					domains, err := w.processBundle()
					pip.DebugPrintf("[%s] bundle processed, err: %v\n", name, err)
					if err != nil {
						return nil, nil, err
					}
					// Return the extracted domains.
					return domains, w.outChs, nil
				}
				return nil, nil, nil
			},
		),
		pip.WithOnNoMoreData[*Certificate, *DirtyDomain](
			func() ([]*DirtyDomain, []int, error) {
				domains, err := w.processBundle()
				return domains, w.outChs, err
			},
		),
	)

	return w
}

// processBundle processes a bundle of certificates and extracts their associated domains.
// The function resets the certificate bundle slice to zero size after it is done.
func (w *CertPtrWorker) processBundle() ([]*DirtyDomain, error) {
	pip.DebugPrintf("[%s] processing bundle\n", w.Stage.Name)
	if len(w.Certs) == 0 {
		return nil, nil
	}

	// Insert the certificates into the DB.
	if err := w.insertCertificates(); err != nil {
		return nil, fmt.Errorf("inserting certificates at worker %d: %w", w.Id, err)
	}

	// Extract the associated domain objects. The domains stay in w.Domains.
	domains := w.extractDomains()

	w.Certs = w.Certs[:0] // Reuse storage, but reset slice.

	return domains, nil
}

func (w *CertPtrWorker) insertCertificates() error {
	// Reuse storage for the data translation.
	w.cacheIds = w.cacheIds[:len(w.Certs)]
	w.cacheParents = w.cacheParents[:len(w.Certs)]
	w.cacheExpirations = w.cacheExpirations[:len(w.Certs)]
	w.cachePayloads = w.cachePayloads[:len(w.Certs)]

	for i, c := range w.Certs {
		w.cacheIds[i] = c.CertID
		w.cacheParents[i] = c.ParentID
		w.cacheExpirations[i] = c.Cert.NotAfter
		w.cachePayloads[i] = c.Cert.Raw
	}

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

	return w.Conn.UpdateCerts(
		w.Ctx,
		w.cacheIds,
		w.cacheParents,
		w.cacheExpirations,
		w.cachePayloads,
	)
}

// extractDomains extract the associated domains stored in the Certs field and places them in the
// Domains and outChs fields.
func (w *CertPtrWorker) extractDomains() []*DirtyDomain {
	// Reuse the storage.
	w.outChs = w.outChs[:0]

	// For each name in each cert, generate a DirtyDomain object and send it to the manager.
	domains := make([]*DirtyDomain, 0, len(w.Certs))
	for _, c := range w.Certs {
		for _, name := range c.Names {
			domains = append(domains, &DirtyDomain{
				DomainID: w.hasher.HashStringCopy(name),
				CertID:   c.CertID,
				Name:     name,
			})
			w.outChs = append(w.outChs,
				int(w.Manager.ShardFuncDomain(&domains[len(domains)-1].DomainID)),
			)
		}
	}
	return domains
}
