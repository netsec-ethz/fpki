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
	Worker
	IncomingChan chan Certificate
	hasher       common.Hasher

	// Cache for the domain ID storage after hash.
	cacheDomainIdHash []common.SHA256Output
	// Cache storage arrays used to unfold Certificate objects into the DB fields.
	cacheIds         []common.SHA256Output
	cacheParents     []*common.SHA256Output
	cacheExpirations []time.Time
	cachePayloads    [][]byte

	// Cache storage arrays used to create DirtyDomain objects. We don't need a certificate ID
	// storage, as we can reuse the one above: never used concurrently.
	// cacheDomainIds []*common.SHA256Output
	// cacheNames     []string
	cacheDomains []DirtyDomain

	dedupStorage map[common.SHA256Output]struct{} // For dedup to not allocate.
}

func NewCertWorker(ctx context.Context, id int, m *Manager, conn db.Conn) *CertWorker {
	w := &CertWorker{
		Worker: *newBaseWorker(ctx, id, m, conn),
		hasher: *common.NewHasher(),

		cacheDomainIdHash: make([]common.SHA256Output, 0, m.MultiInsertSize),

		cacheIds:         make([]common.SHA256Output, 0, m.MultiInsertSize),
		cacheParents:     make([]*common.SHA256Output, 0, m.MultiInsertSize),
		cacheExpirations: make([]time.Time, 0, m.MultiInsertSize),
		cachePayloads:    make([][]byte, 0, m.MultiInsertSize),

		cacheDomains: make([]DirtyDomain, 0, 2*m.MultiInsertSize), // estimates 2 names per cert

		dedupStorage: make(map[common.SHA256Output]struct{}, m.MultiInsertSize),
	}

	return w
}

func (w *CertWorker) Resume() {
	w.Worker.Resume()
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

	// var domain DirtyDomain
	// _=domain
	// for _,c:=range certs {
	// 	for _, name := range c.Names {

	// 		// domainID := w.hasher.HashCopy([]byte(name))
	// 		w.hasher.Hash(&w.cacheDomainIdHash[i], []byte(name))
	// 		domain  = DirtyDomain{
	// 			DomainID: &w.cacheDomainIdHash[i],
	// 			CertID:   c.CertID,
	// 			Name:     name,
	// 		}
	// 		i++
	// 	}
	// }
	// return nil
	w.extractDomains(certs)

	for _, d := range w.cacheDomains {
		w.Manager.IncomingDomainChan <- d
	}

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

// extractDomains inspects the Certificate slice and returns one entry per name in each certificate.
// E.g. if certs contains two certificates, the first one with one name, and the second with two,
// extractDomains will return three entries.
// Each one of the returned slices has the same length.
// The domains are extracted into this CertWorker's cacheDomain slice.
func (w *CertWorker) extractDomains(certs []Certificate) {
	// Clear storage (but preserve it).
	w.cacheDomainIdHash = w.cacheDomainIdHash[:0]
	w.cacheDomains = w.cacheDomains[:0]

	i := 0
	for _, c := range certs {
		// Iff the certificate is a leaf certificate it will have a non-nil names slice: insert
		// one entry per name.
		for _, name := range c.Names {
			// Prepare cache for the hash.
			w.cacheDomainIdHash = append(w.cacheDomainIdHash, common.SHA256Output{})
			// domainID := common.SHA256Hash32Bytes([]byte(name))
			// domainID := common.SHA256Output{}
			// domainID := w.hasher.HashCopy([]byte(name))
			w.hasher.Hash(&w.cacheDomainIdHash[i], []byte(name))
			w.cacheDomains = append(w.cacheDomains, DirtyDomain{
				DomainID: w.cacheDomainIdHash[i],
				CertID:   c.CertID,
				Name:     name,
			})
			i++
		}
	}
	w.cacheDomains = w.cacheDomains[:i]
}
