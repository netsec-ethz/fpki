package updater

import (
	"bytes"
	"sort"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/mapserver/common"
)

// extractCertDomains: get domain from cert: {Common Name, SANs}
func extractCertDomains(cert *x509.Certificate) []string {
	domains := make(uniqueStringSet)
	if len(cert.Subject.CommonName) != 0 {
		domains[cert.Subject.CommonName] = struct{}{}
	}

	for _, dnsName := range cert.DNSNames {
		domains[dnsName] = struct{}{}
	}

	result := []string{}
	for k := range domains {
		result = append(result, k)
	}
	return result
}

// sort domain entries
func sortDomainEntry(domainEntry *common.DomainEntry) {
	// sort CA entries
	sort.Slice(domainEntry.CAEntry, func(j, k int) bool {
		if len(domainEntry.CAEntry[j].CAHash) == len(domainEntry.CAEntry[k].CAHash) {
			return bytes.Compare(domainEntry.CAEntry[j].CAHash, domainEntry.CAEntry[k].CAHash) == -1
		}
		return len(domainEntry.CAEntry[j].CAHash) < len(domainEntry.CAEntry[k].CAHash)
	})

	// sort domain certs in one CA entry
	for i := range domainEntry.CAEntry {
		sort.Slice(domainEntry.CAEntry[i].DomainCerts, func(j, k int) bool {
			if len(domainEntry.CAEntry[i].DomainCerts[j]) == len(domainEntry.CAEntry[i].DomainCerts[k]) {
				return bytes.Compare(domainEntry.CAEntry[i].DomainCerts[j], domainEntry.CAEntry[i].DomainCerts[k]) == -1
			}
			return len(domainEntry.CAEntry[i].DomainCerts[j]) < len(domainEntry.CAEntry[i].DomainCerts[k])
		})
	}
}
