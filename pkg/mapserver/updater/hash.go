package updater

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
)

// UpdateInput: key-value pair for updating
// key: hash of domain name
// value: hash of serilised DomainEntry
type UpdateInput struct {
	Key   [32]byte
	Value []byte
}

// HashDomainEntriesThenSort: hash the DomainEntry, then sort them according to key
func HashDomainEntriesThenSort(domainEntries []common.DomainEntry) ([]UpdateInput, error) {
	result := []UpdateInput{}
	for _, v := range domainEntries {
		domainEntryBytes, err := common.SerialiseDomainEntry(&v)
		if err != nil {
			return nil, fmt.Errorf("HashDomainEntriesThenSort | SerialiseDomainEnrty | %w", err)
		}
		var domainHash db.DomainHash
		copy(domainHash[:], trie.Hasher([]byte(v.DomainName)))
		hashInput := UpdateInput{
			Key:   domainHash,
			Value: trie.Hasher(domainEntryBytes),
		}
		result = append(result, hashInput)
	}

	// sort according to key
	sort.Slice(result, func(i, j int) bool {
		return bytes.Compare(result[i].Key[:], result[j].Key[:]) == -1
	})

	return result, nil
}
