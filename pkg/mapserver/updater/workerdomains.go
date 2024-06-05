package updater

import (
	"context"
	"fmt"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/util"
)

type DomainWorker struct {
	Worker
	IncomingChan chan *DirtyDomain
}

func NewDomainWorker(ctx context.Context, id int, m *Manager, conn db.Conn) *DomainWorker {
	w := &DomainWorker{
		Worker: *newBaseWorker(ctx, id, m, conn),
	}

	return w
}

func (w *DomainWorker) Resume() {
	w.Worker.Resume()
	w.IncomingChan = make(chan *DirtyDomain)
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
			w.addError(w.processBundle(domains))
			// Continue reading certificates until incomingChan is closed.
			domains = domains[:0] // Reuse storage, but reset elements
		}
	}

	// Process the last (possibly empty) batch.
	w.addError(w.processBundle(domains))
	// Signal that we have finished working.
	w.closeErrors()
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
	}

	// Remove duplicates.
	util.DeduplicateSlice(
		func(i int) [2]common.SHA256Output {
			return [2]common.SHA256Output{
				// The bundle of both the domain AND cert ID has to be unique.
				*domainIDs[i],
				*certIDs[i],
			}
		},
		util.Wrap(&domainIDs),
		util.Wrap(&domainNames),
		util.Wrap(&certIDs),
	)

	// Update dirty and domain table.
	if err := w.Conn.InsertDomainsIntoDirty(w.Ctx, domainIDs); err != nil {
		return fmt.Errorf("inserting domains at worker %d: %w", w.Id, err)
	}

	if err := w.Conn.UpdateDomains(w.Ctx, domainIDs, domainNames); err != nil {
		return fmt.Errorf("inserting domains at worker %d: %w", w.Id, err)
	}
	// Update domain_certs.
	if err := w.Conn.UpdateDomainCerts(w.Ctx, domainIDs, certIDs); err != nil {
		return fmt.Errorf("inserting domains at worker %d: %w", w.Id, err)
	}

	return nil
}
