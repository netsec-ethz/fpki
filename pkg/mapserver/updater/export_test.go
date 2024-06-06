package updater

import (
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
)

func (w *CertWorker) ExtractDomains(certs []Certificate) []DirtyDomain {
	w.extractDomains(certs)
	return w.cacheDomains
}

func (w *CertWorker) ProcessBundle(certs []Certificate) error {
	return w.processBundle(certs)
}

func (w *CertWorker) CloneCerts() []common.SHA256Output {
	return w.cacheIds
}
func (w *CertWorker) CloneParents() []*common.SHA256Output {
	return w.cacheParents
}
func (w *CertWorker) CloneExpirations() []time.Time {
	return w.cacheExpirations
}
func (w *CertWorker) ClonePayloads() [][]byte {
	return w.cachePayloads
}

func (w *DomainWorker) ProcessBundle(domains []DirtyDomain) error {
	return w.processBundle(domains)
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
