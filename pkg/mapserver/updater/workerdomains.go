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
	IncomingChan   chan *DirtyDomain
	cloneDomainIDs []*common.SHA256Output // to avoid calling malloc when we run dedup.
	cloneCertIDs   []*common.SHA256Output
	cloneNames     []string
}

func NewDomainWorker(ctx context.Context, id int, m *Manager, conn db.Conn) *DomainWorker {
	w := &DomainWorker{
		Worker:         *newBaseWorker(ctx, id, m, conn),
		cloneDomainIDs: make([]*common.SHA256Output, 0, m.MultiInsertSize),
		cloneCertIDs:   make([]*common.SHA256Output, 0, m.MultiInsertSize),
		cloneNames:     make([]string, 0, m.MultiInsertSize),
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

	// Update dirty table.
	// Remove duplicates for the dirty table insertion.
	w.cloneDomainIDs = append(w.cloneDomainIDs[:0], domainIDs...)
	util.DeduplicateSlice(
		util.WithSlicePtr(w.cloneDomainIDs),
		util.Wrap(&w.cloneDomainIDs),
	)
	if err := w.Conn.InsertDomainsIntoDirty(w.Ctx, w.cloneDomainIDs); err != nil {
		return fmt.Errorf("inserting domains at worker %d: %w", w.Id, err)
	}

	// Update domains table.
	// Remove duplicates (domainID,name)
	w.cloneDomainIDs = append(w.cloneDomainIDs[:0], domainIDs...) // clone again (was modified).
	w.cloneNames = append(w.cloneNames[:0], domainNames...)
	type idName struct {
		id   common.SHA256Output
		name string
	}
	util.DeduplicateSlice(
		func(i int) idName {
			return idName{
				id:   *w.cloneDomainIDs[i],
				name: w.cloneNames[i],
			}
		},
		util.Wrap(&w.cloneDomainIDs),
		util.Wrap(&w.cloneNames),
	)
	if err := w.Conn.UpdateDomains(w.Ctx, w.cloneDomainIDs, w.cloneNames); err != nil {
		return fmt.Errorf("inserting domains at worker %d: %w", w.Id, err)
	}

	// Update domain_certs.
	// Remove duplicates (domainID, certID)
	w.cloneDomainIDs = append(w.cloneDomainIDs[:0], domainIDs...) // again
	w.cloneCertIDs = append(certIDs[:0], certIDs...)
	util.DeduplicateSlice(
		func(i int) [2]common.SHA256Output {
			return [2]common.SHA256Output{
				*w.cloneDomainIDs[i],
				*w.cloneCertIDs[i],
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
