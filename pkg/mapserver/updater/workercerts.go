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

// const AutoFlushTimeout = time.Millisecond

const AutoFlushTimeout = 5 * time.Second // deleteme

type WorkerCerts struct {
	Id           int
	Ctx          context.Context
	Manager      *Manager
	Conn         db.Conn
	IncomingCert chan *Certificate
	flushCertsCh chan struct{} // signals a flush of the certificates in buffer
	doneCertsCh  chan struct{}
}

func NewWorkerCerts(ctx context.Context, id int, m *Manager, conn db.Conn) *WorkerCerts {
	w := &WorkerCerts{
		Id:           id,
		Ctx:          ctx,
		Manager:      m,
		Conn:         conn,
		IncomingCert: make(chan *Certificate),
		flushCertsCh: make(chan struct{}),
		doneCertsCh:  make(chan struct{}),
	}
	w.Resume()

	return w
}

func (w *WorkerCerts) Resume() {
	go w.processAllCerts()
}

func (w *WorkerCerts) WaitCerts() {
	<-w.doneCertsCh
}

// Flush makes this worker send its data to DB even if it is not enough to make up a bundle.
func (w *WorkerCerts) Flush() {
	w.FlushCerts()
}

func (w *WorkerCerts) FlushCerts() {
	w.flushCertsCh <- struct{}{}
}

func (w *WorkerCerts) processAllCerts() {
	// Create a certificate slice where all the received certificates will end up.
	certs := make([]*Certificate, 0, w.Manager.MultiInsertSize)
	// Read all certificates until the manager signals to stop.
	for !w.Manager.stopping.Load() {
		fmt.Printf("deleteme manager stopping? %v\n", w.Manager.stopping.Load())
		// Get the certificate bundle. Or a partial one.
		w.getCertsOrTimeout(&certs, AutoFlushTimeout)
		// deleteme reporting of IDs
		IDs := make([]string, len(certs))
		for i, c := range certs {
			IDs[i] = hex.EncodeToString(c.CertID[:])
		}
		if len(IDs) > 0 {
			fmt.Printf("[worker %2d] inserting certificates, IDs:\n%s\n",
				w.Id, strings.Join(IDs, "\n"))
		}

		err := w.processCertificateBundle(certs)
		if err != nil {
			panic(err) // deleteme
		}
		fmt.Println("deleteme looping again?")
	}
	fmt.Printf("deleteme manager stopping ? %v\n", w.Manager.stopping.Load())
	w.doneCertsCh <- struct{}{}
}

// getCertsOrTimeout returns a certificate bundle of MultiInsertSize certificates, or it
// times out and returns whatever it could read.
// If Flush is called upon this worker, it will immediately return the read certificates.
// The certificates are returned inside the slice passed as pointer in the arguments.
// The function returns false if
func (w *WorkerCerts) getCertsOrTimeout(
	pCerts *[]*Certificate,
	maxWait time.Duration,
) {
	// Derive when we would timeout if taking too long.
	waitTime := time.After(maxWait)
	// Prepare the return slice for the certificates, keep storage.
	*pCerts = (*pCerts)[:0]
	for {
		select {
		case cert := <-w.IncomingCert:
			*pCerts = append(*pCerts, cert)
			if len(*pCerts) == w.Manager.MultiInsertSize {
				// It is already big enough.
				return
			}
		case <-waitTime:
			fmt.Printf("deleteme [%2d] timeout waiting for certs\n", w.Id)
			return
		case <-w.flushCertsCh:
			fmt.Printf("deleteme [%2d] flushed certs\n", w.Id)
			return
		}
	}
}

func (w *WorkerCerts) processCertificateBundle(certs []*Certificate) error {
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
	fmt.Println("deleteme done processing certs and sending domains")

	return nil
}

func (w *WorkerCerts) insertCertificates(certs []*Certificate) error {
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
func (w *WorkerCerts) extractDomains(
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
