package db

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/netsec-ethz/fpki/pkg/common"
	//"time"
)

// used during main thread and worker thread
type readKeyResult struct {
	Keys []common.SHA256Output
	Err  error
}

// ********************************************************************
//                Read functions for Tree table
// ********************************************************************

// RetrieveOneKeyValuePair: Retrieve one single key-value pair
func (c *mysqlDB) RetrieveOneKeyValuePairTreeStruc(ctx context.Context, key common.SHA256Output) (*KeyValuePair, error) {
	keyValuePair, err := retrieveOneKeyValuePair(ctx, c.prepGetValueTree, key)
	if err != nil {
		return nil, fmt.Errorf("RetrieveOneKeyValuePairTreeStruc | %w", err)
	}
	return keyValuePair, nil
}

// RetrieveKeyValuePairFromTreeStruc: Retrieve a list of key-value pairs from DB. Multi-threaded
func (c *mysqlDB) RetrieveKeyValuePairTreeStruc(ctx context.Context, key []common.SHA256Output, numOfWorker int) ([]KeyValuePair, error) {
	stmt := c.prepGetValueTree

	// if work is less than number of worker
	if len(key) < numOfWorker {
		numOfWorker = len(key)
	}

	count := len(key)
	step := count / numOfWorker

	resultChan := make(chan keyValueResult)
	for r := 0; r < numOfWorker-1; r++ {
		go fetchKeyValuePairWorker(resultChan, key[r*step:r*step+step], stmt, ctx)
	}
	// let the final one do the rest of the work
	go fetchKeyValuePairWorker(resultChan, key[(numOfWorker-1)*step:count], stmt, ctx)

	finishedWorker := 0
	keyValuePairs := []KeyValuePair{}

	for numOfWorker > finishedWorker {
		newResult := <-resultChan
		if newResult.Err != nil {
			return nil, fmt.Errorf("RetrieveKeyValuePairMultiThread | %w", newResult.Err)
		}
		keyValuePairs = append(keyValuePairs, newResult.Pairs...)
		finishedWorker++
	}

	return keyValuePairs, nil
}

// ********************************************************************
//                Read functions for domain entries table
// ********************************************************************

// RetrieveOneKeyValuePairDomainEntries: Retrieve one key-value pair from domain entries table
func (c *mysqlDB) RetrieveOneKeyValuePairDomainEntries(ctx context.Context, key common.SHA256Output) (*KeyValuePair, error) {
	keyValuePair, err := retrieveOneKeyValuePair(ctx, c.prepGetValueDomainEntries, key)
	if err != nil {
		return nil, fmt.Errorf("RetrieveOneKeyValuePairDomainEntries | %w", err)
	}
	return keyValuePair, nil
}

func (c *mysqlDB) RetrieveKeyValuePairDomainEntries(ctx context.Context, key []common.SHA256Output, numOfWorker int) ([]KeyValuePair, error) {
	stmt := c.prepGetValueDomainEntries

	// if work is less than number of worker
	if len(key) < numOfWorker {
		numOfWorker = len(key)
	}

	count := len(key)
	step := count / numOfWorker

	resultChan := make(chan keyValueResult)
	for r := 0; r < numOfWorker-1; r++ {
		go fetchKeyValuePairWorker(resultChan, key[r*step:r*step+step], stmt, ctx)
	}
	// let the final one do the rest of the work
	go fetchKeyValuePairWorker(resultChan, key[(numOfWorker-1)*step:count], stmt, ctx)

	finishedWorker := 0
	keyValuePairs := []KeyValuePair{}

	for numOfWorker > finishedWorker {
		newResult := <-resultChan
		if newResult.Err != nil {
			return nil, fmt.Errorf("RetrieveKeyValuePairMultiThread | %w", newResult.Err)
		}
		keyValuePairs = append(keyValuePairs, newResult.Pairs...)
		finishedWorker++
	}

	return keyValuePairs, nil
}

// ********************************************************************
//                Read functions for updates table
// ********************************************************************

// RetrieveUpdatedDomainHashes: Get updated domains name hashes from updates table
func (c *mysqlDB) RetrieveUpdatedDomainHashesUpdates(ctx context.Context, perQueryLimit int) ([]common.SHA256Output, error) {
	count, err := c.GetCountOfUpdatesDomainsUpdates(ctx)
	if err != nil {
		return nil, fmt.Errorf("RetrieveUpdatedDomainHashes_Updates | RetrieveTableRowsCount | %w", err)
	}

	// if work is less than number of worker
	numberOfWorker := 1
	if count > perQueryLimit {
		numberOfWorker = count/perQueryLimit + 1
	}

	var step int
	if numberOfWorker == 1 {
		step = count
	} else {
		step = count / numberOfWorker
	}

	resultChan := make(chan readKeyResult)
	for r := 0; r < numberOfWorker-1; r++ {
		go fetchKeyWorker(resultChan, r*step, r*step+step, ctx, c.db)
	}
	// let the final one do the rest of the work
	go fetchKeyWorker(resultChan, (numberOfWorker-1)*step, count+1, ctx, c.db)

	finishedWorker := 0
	keys := []common.SHA256Output{}

	// get response
	for numberOfWorker > finishedWorker {
		newResult := <-resultChan
		if newResult.Err != nil {
			switch {
			case newResult.Err == sql.ErrNoRows:
				continue
			case newResult.Err != sql.ErrNoRows:
				return nil, fmt.Errorf("RetrieveUpdatedDomainHashes_Updates | %w", newResult.Err)
			}
		}
		keys = append(keys, newResult.Keys...)
		finishedWorker++
	}

	if count != len(keys) {
		return nil, fmt.Errorf("RetrieveUpdatedDomainHashes_Updates | incomplete fetching")
	}

	err = c.TruncateUpdatesTableUpdates(ctx)
	if err != nil {
		return nil, fmt.Errorf("RetrieveUpdatedDomainHashes_Updates | TruncateUpdatesTable | %w", err)
	}

	return keys, nil
}

// CountUpdates: Get number of entries in updates table
func (c *mysqlDB) GetCountOfUpdatesDomainsUpdates(ctx context.Context) (int, error) {
	stmt, err := c.db.Prepare("SELECT COUNT(*) FROM updates")
	if err != nil {
		return 0, fmt.Errorf("CountUpdates | Prepare | %w", err)
	}

	var number int
	err = stmt.QueryRow().Scan(&number)
	if err != nil {
		return 0, fmt.Errorf("CountUpdates | Scan | %w", err)
	}
	stmt.Close()
	return number, nil
}

// ********************************************************************
//                             Common
// ********************************************************************

func retrieveOneKeyValuePair(ctx context.Context, stmt *sql.Stmt, key common.SHA256Output) (*KeyValuePair, error) {
	var value []byte
	result := stmt.QueryRow(key[:])
	err := result.Scan(&value)
	if err != nil {
		switch {
		case err != sql.ErrNoRows:
			return nil, fmt.Errorf("retrieveOneKeyValuePair | Scan | %w", err)
		case err == sql.ErrNoRows:
			return nil, nil
		}
	}

	return &KeyValuePair{Key: key, Value: value}, nil
}
