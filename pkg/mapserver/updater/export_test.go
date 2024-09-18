package updater

import (
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
)

func (w *CertWorker) ProcessBundle() error {
	return w.processBundle()
}

func (w *CertWorker) CacheIds() []common.SHA256Output {
	return w.cacheIds
}
func (w *CertWorker) CacheParents() []*common.SHA256Output {
	return w.cacheParents
}
func (w *CertWorker) CacheExpirations() []time.Time {
	return w.cacheExpirations
}
func (w *CertWorker) CachePayloads() [][]byte {
	return w.cachePayloads
}

func (w *CertPtrWorker) ProcessBundle() ([]*DirtyDomain, error) {
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

func (w *DomainWorker) ProcessBundle() error {
	return w.processBundle()
}

func (w *DomainWorker) CloneDomainIDs() []common.SHA256Output {
	return w.cloneDomainIDs
}

func (w *DomainWorker) CloneNames() []string {
	return w.cloneNames
}

func (w *DomainWorker) CloneCertIDs() []common.SHA256Output {
	return w.cloneCertIDs
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
