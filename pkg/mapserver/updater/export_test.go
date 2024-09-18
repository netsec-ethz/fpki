package updater

import (
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
)

func (w *CertPtrWorker) ProcessBundle() error {
	return w.processBundle()
}

func (w *CertPtrWorker) CacheIds() []common.SHA256Output {
	return w.cacheIds
}
func (w *CertPtrWorker) CacheParents() []*common.SHA256Output {
	return w.cacheParents
}
func (w *CertPtrWorker) CacheExpirations() []time.Time {
	return w.cacheExpirations
}
func (w *CertPtrWorker) CachePayloads() [][]byte {
	return w.cachePayloads
}

func (w *DomainPtrWorker) ProcessBundle() error {
	return w.processBundle()
}

func (w *DomainPtrWorker) CloneDomainIDs() []common.SHA256Output {
	return w.cloneDomainIDs
}

func (w *DomainPtrWorker) CloneNames() []string {
	return w.cloneNames
}

func (w *DomainPtrWorker) CloneCertIDs() []common.SHA256Output {
	return w.cloneCertIDs
}
