package updater

import (
	"context"
	"fmt"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	mapCommon "github.com/netsec-ethz/fpki/pkg/mapserver/common"
)

// retrieveAffectedDomainFromDB: get affected domain entries from db
func (mapUpdater *MapUpdater) retrieveAffectedDomainFromDB(affectedDomainsMap map[common.SHA256Output]byte,
	readerNum int) (map[common.SHA256Output]*mapCommon.DomainEntry, error) {

	// list of domain hashes to fetch the domain entries from db
	affectedDomainHash := []common.SHA256Output{}
	for k := range affectedDomainsMap {
		affectedDomainHash = append(affectedDomainHash, k)
	}

	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	// read key-value pair from DB
	domainPair, err := mapUpdater.dbConn.RetrieveKeyValuePairDomainEntries(ctx, affectedDomainHash, readerNum)
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
func (mapUpdater *MapUpdater) writeChangesToDB(updatesToDomainEntriesTable []db.KeyValuePair,
	updatesToUpdatesTable []common.SHA256Output) (int, error) {

	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	err, _ := mapUpdater.dbConn.UpdateKeyValuesDomainEntries(ctx, updatesToDomainEntriesTable)
	if err != nil {
		return 0, fmt.Errorf("writeToDomainEntriesTable | UpdateKeyValuePairBatches | %w", err)
	}

	_, err = mapUpdater.dbConn.AddUpdatedDomainHashesUpdates(ctx, updatesToUpdatesTable)
	if err != nil {
		return 0, fmt.Errorf("writeToUpdateTable | InsertIgnoreKeyBatches | %w", err)
	}

	return len(updatesToUpdatesTable), nil
}

// domain bytes -> domain entries
func parseDomainBytes(keyValuePairs []db.KeyValuePair) (map[common.SHA256Output]*mapCommon.DomainEntry, error) {
	result := make(map[common.SHA256Output]*mapCommon.DomainEntry)
	for _, pair := range keyValuePairs {
		newPair, err := mapCommon.DesrialiseDomainEntry(pair.Value)
		if err != nil {
			return nil, fmt.Errorf("parseDomainBytes | DesrialiseDomainEntry | %w", err)
		}
		result[pair.Key] = newPair
	}
	return result, nil
}
