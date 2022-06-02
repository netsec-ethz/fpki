package updater

import (
	"context"
	"fmt"
	"time"

	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/common"
)

// retrieveAffectedDomainFromDB: get affected domain entries from db
func (mapUpdator *MapUpdater) retrieveAffectedDomainFromDB(affectedDomainsMap map[string]byte,
	readerNum int) (map[string]*common.DomainEntry, error) {

	// list of domain hashes to fetch the domain entries from db
	affectedDomainHash := []string{}
	for k := range affectedDomainsMap {
		affectedDomainHash = append(affectedDomainHash, k)
	}

	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	// read key-value pair from DB
	domainPair, err := mapUpdator.dbConn.RetrieveKeyValuePair_DomainEntries(ctx, affectedDomainHash, readerNum)
	if err != nil {
		return nil, fmt.Errorf("UpdateDomainEntries | RetrieveKeyValuePairMultiThread | %w", err)
	}

	// parse the key-value pair -> domain map
	domainEntriesMap, err := parseDomainBytes(domainPair)
	if err != nil {
		return nil, fmt.Errorf("UpdateDomainEntries | parseDomainBytes | %w", err)
	}
	return domainEntriesMap, nil
}

// commit changes to db
func (mapUpdator *MapUpdater) writeChangesToDB(updatesToDomainEntriesTable []db.KeyValuePair,
	updatesToUpdatesTable []string) (int, error) {

	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	err, _ := mapUpdator.dbConn.UpdateKeyValues_DomainEntries(ctx, updatesToDomainEntriesTable)
	if err != nil {
		return 0, fmt.Errorf("writeToDomainEntriesTable | UpdateKeyValuePairBatches | %w", err)
	}

	_, err = mapUpdator.dbConn.AddUpdatedDomainHashes_Updates(ctx, updatesToUpdatesTable)
	if err != nil {
		return 0, fmt.Errorf("writeToUpdateTable | InsertIgnoreKeyBatches | %w", err)
	}

	return len(updatesToUpdatesTable), nil
}

// domain bytes -> domain entries
func parseDomainBytes(keyValuePairs []db.KeyValuePair) (map[string]*common.DomainEntry, error) {
	result := make(map[string]*common.DomainEntry)
	for _, pair := range keyValuePairs {
		newPair, err := common.DesrialiseDomainEnrty(pair.Value)
		if err != nil {
			return nil, fmt.Errorf("parseDomainBytes | DesrialiseDomainEnrty | %w", err)
		}
		result[pair.Key] = newPair
	}
	return result, nil
}
