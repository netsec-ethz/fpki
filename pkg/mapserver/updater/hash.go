package updater

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/netsec-ethz/fpki/pkg/mapserver/common"
	tire "github.com/netsec-ethz/fpki/pkg/mapserver/tire"
)

func HashDomainEntriesThenSort(domainEntries []common.DomainEntry) ([]common.UpdateInput, error) {
	result := []common.UpdateInput{}
	for _, v := range domainEntries {
		domainEntryBytes, err := common.SerialiseDomainEnrty(&v)
		if err != nil {
			return nil, fmt.Errorf("HashDomainEntriesThenSort | SerialiseDomainEnrty | %w", err)
		}
		hashInput := common.UpdateInput{
			Key:   tire.Hasher([]byte(v.DomainName)),
			Value: tire.Hasher(domainEntryBytes),
		}
		result = append(result, hashInput)
	}

	sort.Slice(result, func(i, j int) bool {
		return bytes.Compare(result[i].Key, result[j].Key) == -1
	})

	return result, nil
}
