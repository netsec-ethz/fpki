package updater

import (
	"context"
	"time"

	"github.com/netsec-ethz/fpki/pkg/db"
)

func (w *Worker) GetCertsOrTimeout(maxWait time.Duration) []*Certificate {
	certs := make([]*Certificate, 0)
	w.getCertsOrTimeout(&certs, maxWait)
	return certs
}

func NewWorkerForTesting(ctx context.Context, m *Manager, conn db.Conn) *Worker {
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
	return w
}
