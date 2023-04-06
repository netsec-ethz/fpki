package updater

import (
	"github.com/netsec-ethz/fpki/pkg/mapserver/common"
)

// sort domain entries
func sortDomainEntry(domainEntry *common.DomainEntry) {
	// // sort CA entries
	// sort.Slice(domainEntry.Entries, func(j, k int) bool {
	// 	if len(domainEntry.Entries[j].CAHash) == len(domainEntry.Entries[k].CAHash) {
	// 		return bytes.Compare(domainEntry.Entries[j].CAHash, domainEntry.Entries[k].CAHash) == -1
	// 	}
	// 	return len(domainEntry.Entries[j].CAHash) < len(domainEntry.Entries[k].CAHash)
	// })

	// // sort domain certs in one CA entry
	// for i := range domainEntry.Entries {
	// 	sort.Slice(domainEntry.Entries[i].DomainCerts, func(j, k int) bool {
	// 		if len(domainEntry.Entries[i].DomainCerts[j]) == len(domainEntry.Entries[i].DomainCerts[k]) {
	// 			return bytes.Compare(domainEntry.Entries[i].DomainCerts[j], domainEntry.Entries[i].DomainCerts[k]) == -1
	// 		}
	// 		return len(domainEntry.Entries[i].DomainCerts[j]) < len(domainEntry.Entries[i].DomainCerts[k])
	// 	})
	// }
}
