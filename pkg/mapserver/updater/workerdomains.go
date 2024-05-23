package updater

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
)

type WorkerDomains struct {
	Id             int
	Ctx            context.Context
	Manager        *Manager
	Conn           db.Conn
	IncomingDomain chan *DirtyDomain
	flushDomainsCh chan struct{} // signals a flush of the domains
	doneDomainsCh  chan struct{}
}

func NewWorkerDomains(ctx context.Context, id int, m *Manager, conn db.Conn) *WorkerDomains {
	w := &WorkerDomains{
		Id:             id,
		Ctx:            ctx,
		Manager:        m,
		Conn:           conn,
		IncomingDomain: make(chan *DirtyDomain),
		flushDomainsCh: make(chan struct{}),
		doneDomainsCh:  make(chan struct{}),
	}
	w.Resume()

	return w
}

func (w *WorkerDomains) Resume() {
	go w.processAllDomains()
}

func (w *WorkerDomains) WaitDomains() {
	<-w.doneDomainsCh
}

// Flush makes this worker send its data to DB even if it is not enough to make up a bundle.
func (w *WorkerDomains) Flush() {
	w.FlushDomains()
}

func (w *WorkerDomains) FlushDomains() {
	w.flushDomainsCh <- struct{}{}
}

func (w *WorkerDomains) processAllDomains() {
	// Create a certificate slice where all the received certificates will end up.
	domains := make([]*DirtyDomain, 0, w.Manager.MultiInsertSize)
	// Read all domains until the manager signals to stop.
	for !w.Manager.stopping.Load() {
		// Get the domain bundle. Or a partial one.
		w.getDomainsOrTimeout(&domains, AutoFlushTimeout)
		// deleteme reporting of IDs
		IDs := make([]string, len(domains))
		for i, d := range domains {
			IDs[i] = hex.EncodeToString(d.DomainID[:])
		}
		if len(IDs) > 0 {
			fmt.Printf("[worker %2d] inserting domains, IDs:\n%s\n",
				w.Id, strings.Join(IDs, "\n"))
		}

		err := w.processDomainBundle(domains)
		if err != nil {
			panic(err) // deleteme
		}
	}
	fmt.Printf("deleteme [%2d] done with domains\n", w.Id)
	w.doneDomainsCh <- struct{}{}
}

func (w *WorkerDomains) getDomainsOrTimeout(
	pDomains *[]*DirtyDomain,
	maxWait time.Duration,
) {
	// Derive when we would timeout if taking too long.
	waitTime := time.After(maxWait)
	// Prepare the return slice for the certificates, keep storage.
	*pDomains = (*pDomains)[:0]
	for {
		select {
		case domain := <-w.IncomingDomain:
			fmt.Printf("deleteme [%2d] got domain %s\n", w.Id, hex.EncodeToString(domain.DomainID[:]))
			*pDomains = append(*pDomains, domain)
			if len(*pDomains) == w.Manager.MultiInsertSize {
				// It is already big enough.
				return
			}
		case <-waitTime:
			fmt.Printf("deleteme [%2d] timeout waiting for domains\n", w.Id)
			return
		case <-w.flushDomainsCh:
			fmt.Printf("deleteme [%2d] flushed domains\n", w.Id)
			return
		}
	}
}

func (w *WorkerDomains) processDomainBundle(domains []*DirtyDomain) error {
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

	// Update dirty and domain table.
	if err := w.insertDomains(domainIDs, domainNames); err != nil {
		return err
	}
	// deleteme
	// // Update domain_certs.
	// return w.insertDomainCerts(domainIDs, certIDs)
	return nil
}

func (w *WorkerDomains) insertDomains(IDs []*common.SHA256Output, domainNames []string) error {
	if err := w.Conn.InsertDomainsIntoDirty(w.Ctx, IDs); err != nil {
		return err
	}
	return w.Conn.UpdateDomains(w.Ctx, IDs, domainNames)
}

func (w *WorkerDomains) insertDomainCerts(domainIDs, certIDs []*common.SHA256Output) error {
	return w.Conn.UpdateDomainCerts(w.Ctx, domainIDs, certIDs)
}
