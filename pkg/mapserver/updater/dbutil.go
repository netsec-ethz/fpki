package updater

import (
	"context"
	"fmt"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	mapCommon "github.com/netsec-ethz/fpki/pkg/mapserver/common"
)

// retrieveAffectedDomainFromDB: get affected domain entries from db
func (mapUpdater *MapUpdater) retrieveAffectedDomainFromDB(ctx context.Context, affectedDomainsMap uniqueSet,
	readerNum int) (map[common.SHA256Output]*mapCommon.DomainEntry, error) {

	// list of domain hashes to fetch the domain entries from db
	affectedDomainHash := make([]common.SHA256Output, 0, len(affectedDomainsMap))
	for k := range affectedDomainsMap {
		affectedDomainHash = append(affectedDomainHash, k)
	}
	// read key-value pair from DB
	domainPair, err := mapUpdater.dbConn.RetrieveKeyValuePairDomainEntries(ctx, affectedDomainHash, readerNum)
	if err != nil {
		return nil, fmt.Errorf("retrieveAffectedDomainFromDB | RetrieveKeyValuePairDomainEntries | %w", err)
	}

	// parse the key-value pair -> domain map
	domainEntriesMap, err := parseDomainBytes(domainPair)
	if err != nil {
		return nil, fmt.Errorf("retrieveAffectedDomainFromDB | parseDomainBytes | %w", err)
	}
	return domainEntriesMap, nil
}

// writeChangesToDB: commit changes to domain entries table and updates table
func (mapUpdater *MapUpdater) writeChangesToDB(ctx context.Context, updatesToDomainEntriesTable []db.KeyValuePair,
	updatesToUpdatesTable []common.SHA256Output) (int, error) {

	_, err := mapUpdater.dbConn.UpdateKeyValuesDomainEntries(ctx, updatesToDomainEntriesTable)
	if err != nil {
		return 0, fmt.Errorf("writeChangesToDB | UpdateKeyValuesDomainEntries | %w", err)
	}

	_, err = mapUpdater.dbConn.AddUpdatedDomainHashesUpdates(ctx, updatesToUpdatesTable)
	if err != nil {
		return 0, fmt.Errorf("writeChangesToDB | AddUpdatedDomainHashesUpdates | %w", err)
	}

	return len(updatesToUpdatesTable), nil
}

// domain bytes -> domain entries
func parseDomainBytes(keyValuePairs []db.KeyValuePair) (map[common.SHA256Output]*mapCommon.DomainEntry, error) {
	result := make(map[common.SHA256Output]*mapCommon.DomainEntry)
	for _, pair := range keyValuePairs {
		newPair, err := mapCommon.DeserializeDomainEntry(pair.Value)
		if err != nil {
			return nil, fmt.Errorf("parseDomainBytes | DeserializeDomainEntry | %w", err)
		}
		result[pair.Key] = newPair
	}
	return result, nil
}
