package updater

import (
	"context"
	"fmt"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/util"
)

type CertWorker struct {
	baseWorker
	IncomingChan chan Certificate
	hasher       common.Hasher

	// Cache storage arrays used to unfold Certificate objects into the DB fields.
	cacheIds         []common.SHA256Output
	cacheParents     []*common.SHA256Output
	cacheExpirations []time.Time
	cachePayloads    [][]byte

	dedupStorage map[common.SHA256Output]struct{} // For dedup to not allocate.
}

func NewCertWorker(ctx context.Context, id int, m *Manager, conn db.Conn) *CertWorker {
	w := &CertWorker{
		baseWorker: *newBaseWorker(ctx, id, m, conn),
		hasher:     *common.NewHasher(),

		cacheIds:         make([]common.SHA256Output, 0, m.MultiInsertSize),
		cacheParents:     make([]*common.SHA256Output, 0, m.MultiInsertSize),
		cacheExpirations: make([]time.Time, 0, m.MultiInsertSize),
		cachePayloads:    make([][]byte, 0, m.MultiInsertSize),

		dedupStorage: make(map[common.SHA256Output]struct{}, m.MultiInsertSize),
	}

	return w
}

func (w *CertWorker) Resume() {
	w.baseWorker.Resume()
	w.IncomingChan = make(chan Certificate)
	go w.resume()
}

// Stop stops processing. This function doesn't wait for the worker to finish. For that, see Wait().
func (w *CertWorker) Stop() {
	close(w.IncomingChan)
}

func (w *CertWorker) resume() {
	// Create a certificate slice where all the received certificates will end up.
	certs := make([]Certificate, 0, w.Manager.MultiInsertSize)

	for cert := range w.IncomingChan {
		certs = append(certs, cert)
		if len(certs) == w.Manager.MultiInsertSize {
			w.addError(w.processBundle(certs))
			// Continue reading certificates until incomingChan is closed.
			certs = certs[:0] // Reuse storage, but reset elements
		}
	}

	// Process the last (possibly empty) batch.
	w.addError(w.processBundle(certs))

	// Signal that we have finished working.
	w.closeErrors()
}

func (w *CertWorker) processBundle(certs []Certificate) error {
	if len(certs) == 0 {
		return nil
	}

	// Insert the certificates into the DB.
	if err := w.insertCertificates(certs); err != nil {
		return fmt.Errorf("inserting certificates at worker %d: %w", w.Id, err)
	}

	// Send the associated domain objects to the manager.
	w.sendDomains(certs)

	return nil
}

func (w *CertWorker) insertCertificates(certs []Certificate) error {
	// Reuse storage for the data translation.
	w.cacheIds = w.cacheIds[:len(certs)]
	w.cacheParents = w.cacheParents[:len(certs)]
	w.cacheExpirations = w.cacheExpirations[:len(certs)]
	w.cachePayloads = w.cachePayloads[:len(certs)]

	for i, c := range certs {
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

func (w *CertWorker) sendDomains(certs []Certificate) {
	// For each name in each cert, generate a DirtyDomain object and send it to the manager.
	for _, c := range certs {
		for _, name := range c.Names {
			w.Manager.IncomingDomainChan <- DirtyDomain{
				DomainID: w.hasher.HashStringCopy(name),
				CertID:   c.CertID,
				Name:     name,
			}

		}
	}
}
