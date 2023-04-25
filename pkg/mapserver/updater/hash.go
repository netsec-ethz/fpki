package updater

// UpdateInput: key-value pair for updating
// key: hash of domain name
// value: hash of serilised DomainEntry

// // DeletemeHashDomainEntriesThenSort: hash the DomainEntry, then sort them according to key
// func DeletemeHashDomainEntriesThenSort(domainEntries []mapCommon.DomainEntry) ([]UpdateInput, error) {
// 	result := make([]UpdateInput, 0, len(domainEntries))
// 	for _, v := range domainEntries {
// 		domainEntryBytes, err := mapCommon.SerializeDomainEntry(&v)
// 		if err != nil {
// 			return nil, fmt.Errorf("HashDomainEntriesThenSort | SerializedDomainEntry | %w", err)
// 		}
// 		var domainHash common.SHA256Output
// 		copy(domainHash[:], common.SHA256Hash([]byte(v.DomainName)))
// 		hashInput := UpdateInput{
// 			Key:   domainHash,
// 			Value: common.SHA256Hash(domainEntryBytes),
// 		}
// 		result = append(result, hashInput)
// 	}

// 	// sort according to key
// 	sort.Slice(result, func(i, j int) bool {
// 		return bytes.Compare(result[i].Key[:], result[j].Key[:]) == -1
// 	})

// 	return result, nil
// }
