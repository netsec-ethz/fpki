package updater

import (
	"context"
	"fmt"
	"time"

	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/common"
)

// retrieveAffectedDomainFromDB: get affected domain entries from db
func (mapUpdator *MapUpdater) retrieveAffectedDomainFromDB(affectedDomainsMap map[string]byte, readerNum int) (map[string]*common.DomainEntry, error) {
	// list of domain hashes to fetch the domain entries from db
	affectedDomainHash := []string{}
	for k := range affectedDomainsMap {
		affectedDomainHash = append(affectedDomainHash, k)
	}

	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	// read key-value pair from DB
	domainPair, err := mapUpdator.dbConn.RetrieveKeyValuePairMultiThread(ctx, affectedDomainHash, readerNum, db.DomainEntries)
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
func (mapUpdator *MapUpdater) writeChangesToDB(updatesToDomainEntriesTable []db.KeyValuePair, updatesToUpdatesTable []string) (int, error) {

	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	err, _ := mapUpdator.dbConn.UpdateKeyValuePairBatches(ctx, updatesToDomainEntriesTable, db.DomainEntries)
	if err != nil {
		return 0, fmt.Errorf("writeToDomainEntriesTable | UpdateKeyValuePairBatches | %w", err)
	}

	_, err = mapUpdator.dbConn.InsertIgnoreKeyBatches(ctx, updatesToUpdatesTable)
	if err != nil {
		return 0, fmt.Errorf("writeToUpdateTable | InsertIgnoreKeyBatches | %w", err)
	}
	/* multi-thread version of writing; not useful. Bottleneck is the updating of domain entries
	fmt.Println()
	start := time.Now()
	// write to db, multi-thread
	resultChan := make(chan error)
	// write changes to domainEntries table
	go writeToDomainEntriesTable(ctx, dbConn, updatesToDomainEntriesTable, resultChan)
	// write changes to updates table
	go writeToUpdateTable(ctx, dbConn, updatesToUpdatesTable, resultChan)

	writeErr := <-resultChan
	if writeErr != nil {
		return 0, fmt.Errorf("writeChangesToDB | Write DB error | %w", writeErr)
	}
	writeErr = <-resultChan
	if writeErr != nil {
		return 0, fmt.Errorf("writeChangesToDB | Write DB error | %w", writeErr)
	}

	end := time.Now()
	fmt.Println("time to write to db                       ", end.Sub(start), " num of writes: ", len(updatesToDomainEntriesTable)+len(updatesToUpdatesTable))
	fmt.Println()

	return len(updatesToUpdatesTable), nil
	*/
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

/*
// write to domainEntries table
func writeToDomainEntriesTable(ctx context.Context, dbConn db.Conn, input []db.KeyValuePair, resultChan chan error) {
	start := time.Now()
	err, _ := dbConn.UpdateKeyValuePairBatches(ctx, input, db.DomainEntries)
	if err != nil {
		resultChan <- fmt.Errorf("writeToDomainEntriesTable | UpdateKeyValuePairBatches | %w", err)
	}
	end := time.Now()
	fmt.Println("time to update domain entry table: ", end.Sub(start))
	resultChan <- nil
}

// write to updates table
func writeToUpdateTable(ctx context.Context, dbConn db.Conn, input []string, resultChan chan error) {
	start := time.Now()
	_, err := dbConn.InsertIgnoreKeyBatches(ctx, input)
	if err != nil {
		resultChan <- fmt.Errorf("writeToUpdateTable | InsertIgnoreKeyBatches | %w", err)
	}
	end := time.Now()
	fmt.Println("time to update updateds table: ", end.Sub(start))
	resultChan <- nil
}
*/
