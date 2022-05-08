package mapserver

import (
	"bytes"

	"sort"

	tire "github.com/netsec-ethz/fpki/pkg/mapserver/tire"
)

func HashDomainEntriesThenSort(domainEntries []DomainEntry) []UpdateInput {
	result := []UpdateInput{}

	for _, v := range domainEntries {
		hashInput := UpdateInput{
			key:   tire.Hasher([]byte(v.domainName)),
			value: tire.Hasher(append([]byte(v.domainName), flattenBytesSlice(v.certificates)...)),
		}
		result = append(result, hashInput)
	}

	sort.Slice(result, func(i, j int) bool {
		return bytes.Compare(result[i].key, result[j].key) == -1
	})

	return result
}

func flattenBytesSlice(input [][]byte) []byte {
	result := []byte{}
	for _, v := range input {
		result = append(result, v...)
	}
	return result
}
