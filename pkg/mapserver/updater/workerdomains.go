package updater

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
)

type DomainWorker struct {
	Worker
	IncomingChan chan *DirtyDomain
}

func NewDomainWorker(ctx context.Context, id int, m *Manager, conn db.Conn) *DomainWorker {
	w := &DomainWorker{
		Worker:       *newBaseWorker(ctx, id, m, conn),
		IncomingChan: make(chan *DirtyDomain),
	}
	w.Resume()

	return w
}

func (w *DomainWorker) Resume() {
	go w.resume()
}

// Stop stops processing. This function doesn't wait for the worker to finish. For that, see Wait().
func (w *DomainWorker) Stop() {
	close(w.IncomingChan)
}

func (w *DomainWorker) resume() {
	// Create a certificate slice where all the received certificates will end up.
	domains := make([]*DirtyDomain, 0, w.Manager.MultiInsertSize)

	for domain := range w.IncomingChan {
		domains = append(domains, domain)
		if len(domains) == w.Manager.MultiInsertSize {
			if err := w.processBundle(domains); err != nil {
				// Add the error.
				w.addError(err)
				// Continue reading certificates until incomingChan is closed.
			}
			domains = domains[:0] // Reuse storage, but reset elements
		}
	}

	// Process the last (possibly empty) batch.
	w.addError(w.processBundle(domains))
	// Signal that we have finished working.
	w.closeErrors()

	fmt.Printf("[%2d] domain worker is finished\n", w.Id)

	//
	//
	// deleteme
	// // try to settle the DB again by running commit once more on the connection/session
	// _, err := w.Conn.DB().ExecContext(w.Ctx, "COMMIT")
	// if err != nil {
	// 	panic(err)
	// }
}

func (w *DomainWorker) processBundle(domains []*DirtyDomain) error {
	if len(domains) == 0 {
		return nil
	}
	domainIDs := make([]*common.SHA256Output, len(domains))
	domainNames := make([]string, len(domains))
	certIDs := make([]*common.SHA256Output, len(domains))
	for i, d := range domains {
		domainIDs[i] = d.DomainID
		domainNames[i] = d.Name
		certIDs[i] = d.CertID

		// deleteme
		fmt.Printf("[%2d, %p] domain: %s\n", w.Id, w.Manager, hex.EncodeToString(d.DomainID[:]))
	}

	// Update dirty and domain table.
	if err := w.insertDomains(domainIDs, domainNames); err != nil {
		return fmt.Errorf("inserting domains at worker %d: %w", w.Id, err)
	}
	// Update domain_certs.
	return w.insertDomainCerts(domainIDs, certIDs)
}

func (w *DomainWorker) insertDomains(IDs []*common.SHA256Output, domainNames []string) error {
	if err := w.Conn.InsertDomainsIntoDirty(w.Ctx, IDs); err != nil {
		return err
	}
	return w.Conn.UpdateDomains(w.Ctx, IDs, domainNames)
}

func (w *DomainWorker) insertDomainCerts(domainIDs, certIDs []*common.SHA256Output) error {
	return w.Conn.UpdateDomainCerts(w.Ctx, domainIDs, certIDs)
}
