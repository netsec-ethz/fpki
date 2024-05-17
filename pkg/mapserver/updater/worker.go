package updater

import (
	"context"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
)

const AutoFlushTimeout = time.Millisecond

type Worker struct {
	Ctx            context.Context
	Manager        *Manager
	Conn           db.Conn
	IncomingCert   chan *Certificate
	IncomingDomain chan *DirtyDomain
	flushCertsCh   chan struct{} // signals a flush of the certificates in buffer
	flushDomainsCh chan struct{} // signals a flush of the domains
	doneCertsCh    chan struct{}
	doneDomainsCh  chan struct{}
}

func NewWorker(ctx context.Context, m *Manager, conn db.Conn) *Worker {
	w := &Worker{
		Ctx:            ctx,
		Manager:        m,
		Conn:           conn,
		IncomingCert:   make(chan *Certificate),
		IncomingDomain: make(chan *DirtyDomain),
		flushCertsCh:   make(chan struct{}),
		flushDomainsCh: make(chan struct{}),
		doneCertsCh:    make(chan struct{}),
		doneDomainsCh:  make(chan struct{}),
	}
	w.Resume()

	return w
}

func (w *Worker) Resume() {
	go w.processAllCerts()
	go w.processAllDomains()
}

func (w *Worker) WaitCerts() {
	<-w.doneCertsCh
}

func (w *Worker) WaitDomains() {
	<-w.doneDomainsCh
}

// Flush makes this worker send its data to DB even if it is not enough to make up a bundle.
func (w *Worker) Flush() {
	w.FlushCerts()
	w.FlushDomains()
}

func (w *Worker) FlushCerts() {
	w.flushCertsCh <- struct{}{}
}

func (w *Worker) FlushDomains() {
	w.flushDomainsCh <- struct{}{}
}

func (w *Worker) processAllCerts() {
	// Create a certificate slice where all the received certificates will end up.
	certs := make([]*Certificate, 0, w.Manager.MultiInsertSize)
	// Read all certificates until the manager signals to stop.
	for !w.Manager.stopping.Load() {
		// Get the certificate bundle. Or a partial one.
		w.getCertsOrTimeout(&certs, AutoFlushTimeout)
		err := w.processCertificateBundle(certs)
		if err != nil {
			panic(err) // deleteme
		}
	}
	w.doneCertsCh <- struct{}{}
}

func (w *Worker) processAllDomains() {
	// Create a certificate slice where all the received certificates will end up.
	domains := make([]*DirtyDomain, 0, w.Manager.MultiInsertSize)
	// Read all domains until the manager signals to stop.
	for !w.Manager.stopping.Load() {
		// Get the domain bundle. Or a partial one.
		w.getDomainsOrTimeout(&domains, AutoFlushTimeout)
		if err := w.processDomainBundle(domains); err != nil {
			panic(err) // deleteme
		}
	}
	w.doneDomainsCh <- struct{}{}
}

// getCertsOrTimeout returns a certificate bundle of MultiInsertSize certificates, or it
// times out and returns whatever it could read.
// If Flush is called upon this worker, it will immediately return the read certificates.
// The certificates are returned inside the slice passed as pointer in the arguments.
// The function returns false if
func (w *Worker) getCertsOrTimeout(
	pCerts *[]*Certificate,
	maxWait time.Duration,
) {
	// Derive when we would timeout if taking too long.
	waitTime := time.After(maxWait)
	// Prepare the return slice for the certificates, keep storage.
	*pCerts = (*pCerts)[0:]
	for {
		select {
		case cert := <-w.IncomingCert:
			*pCerts = append(*pCerts, cert)
			if len(*pCerts) == w.Manager.MultiInsertSize {
				// It is already big enough.
				return
			}
		case <-waitTime:
			return
		case <-w.flushCertsCh:
			return
		}
	}
}

func (w *Worker) getDomainsOrTimeout(
	pDomains *[]*DirtyDomain,
	maxWait time.Duration,
) {
	// Derive when we would timeout if taking too long.
	waitTime := time.After(maxWait)
	// Prepare the return slice for the certificates, keep storage.
	*pDomains = (*pDomains)[0:]
	for {
		select {
		case domain := <-w.IncomingDomain:
			*pDomains = append(*pDomains, domain)
			if len(*pDomains) == w.Manager.MultiInsertSize {
				// It is already big enough.
				return
			}
		case <-waitTime:
			return
		case <-w.flushDomainsCh:
			return
		}
	}
}

func (w *Worker) processCertificateBundle(certs []*Certificate) error {
	if len(certs) == 0 {
		return nil
	}
	// Insert the certificates into the DB.
	if err := w.insertCertificates(certs); err != nil {
		return err
	}
	domainNames, domainIDs, certInDomainIDs := w.extractDomains(certs)

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

func (w *Worker) processDomainBundle(domains []*DirtyDomain) error {
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
	// Update domain_certs.
	return w.insertDomainCerts(domainIDs, certIDs)
}

func (w *Worker) insertCertificates(certs []*Certificate) error {
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
func (w *Worker) extractDomains(
	certs []*Certificate,
) (
	newDomainNames []string,
	certInDomainsIDs []*common.SHA256Output,
	domainIDs []*common.SHA256Output,
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

func (w *Worker) insertDomains(IDs []*common.SHA256Output, domainNames []string) error {
	if err := w.Conn.InsertDomainsIntoDirty(w.Ctx, IDs); err != nil {
		return err
	}
	return w.Conn.UpdateDomains(w.Ctx, IDs, domainNames)
}

func (w *Worker) insertDomainCerts(domainIDs, certIDs []*common.SHA256Output) error {
	return w.Conn.UpdateDomainCerts(w.Ctx, domainIDs, certIDs)
}
