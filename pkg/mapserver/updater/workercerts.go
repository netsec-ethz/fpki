package updater

import (
	"context"
	"fmt"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
)

type CertWorker struct {
	Worker
	IncomingChan chan *Certificate
}

func NewCertWorker(ctx context.Context, id int, m *Manager, conn db.Conn) *CertWorker {
	w := &CertWorker{
		Worker: *newBaseWorker(ctx, id, m, conn),
	}

	return w
}

func (w *CertWorker) Resume() {
	w.Worker.Resume()
	w.IncomingChan = make(chan *Certificate)
	go w.resume()
}

// Stop stops processing. This function doesn't wait for the worker to finish. For that, see Wait().
func (w *CertWorker) Stop() {
	close(w.IncomingChan)
}

func (w *CertWorker) resume() {
	// Create a certificate slice where all the received certificates will end up.
	certs := make([]*Certificate, 0, w.Manager.MultiInsertSize)

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

func (w *CertWorker) processBundle(certs []*Certificate) error {
	if len(certs) == 0 {
		return nil
	}

	// Insert the certificates into the DB.
	if err := w.insertCertificates(certs); err != nil {
		return fmt.Errorf("inserting certificates at worker %d: %w", w.Id, err)
	}

	domainIDs, domainNames, certInDomainIDs := w.extractDomains(certs)

	for i := range domainIDs {
		d := &DirtyDomain{
			DomainID: domainIDs[i],
			CertID:   certInDomainIDs[i],
			Name:     domainNames[i],
		}
		w.Manager.IncomingDomainChan <- d
	}

	return nil
}

func (w *CertWorker) insertCertificates(certs []*Certificate) error {
	ids := make([]*common.SHA256Output, len(certs))
	parents := make([]*common.SHA256Output, len(certs))
	expirations := make([]*time.Time, len(certs))
	payloads := make([][]byte, len(certs))
	for i, c := range certs {
		ids[i] = c.CertID
		parents[i] = c.ParentID
		expirations[i] = &c.Cert.NotAfter
		payloads[i] = c.Cert.Raw
	}
	return w.Conn.UpdateCerts(w.Ctx, ids, parents, expirations, payloads)
}

// extractDomains inspects the Certificate slice and returns one entry per name in each certificate.
// E.g. if certs contains two certificates, the first one with one name, and the second with two,
// extractDomains will return three entries.
// Each one of the returned slices has the same length.
func (w *CertWorker) extractDomains(
	certs []*Certificate,
) (
	domainIDs []*common.SHA256Output,
	newDomainNames []string,
	certInDomainsIDs []*common.SHA256Output,
) {
	estimatedLeafCount := len(certs)
	newDomainNames = make([]string, 0, estimatedLeafCount)
	certInDomainsIDs = make([]*common.SHA256Output, 0, estimatedLeafCount)
	domainIDs = make([]*common.SHA256Output, 0, estimatedLeafCount)
	for _, c := range certs {
		// Iff the certificate is a leaf certificate it will have a non-nil names slice: insert
		// one entry per name.
		for _, name := range c.Names {
			newDomainNames = append(newDomainNames, name)
			certInDomainsIDs = append(certInDomainsIDs, c.CertID)
			domainID := common.SHA256Hash32Bytes([]byte(name))
			domainIDs = append(domainIDs, &domainID)
		}
	}
	return
}
