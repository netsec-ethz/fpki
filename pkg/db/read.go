package db

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/netsec-ethz/fpki/pkg/common"
)

// used during main thread and worker thread
type readKeyResult struct {
	Keys []common.SHA256Output
	Err  error
}

// RetrieveTreeNode retrieves one single key-value pair from tree table
// Return sql.ErrNoRows if no row is round
func (c *mysqlDB) RetrieveTreeNode(ctx context.Context, key common.SHA256Output) (*KeyValuePair, error) {
	keyValuePair, err := retrieveOneKeyValuePair(ctx, c.prepGetValueTree, key)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("RetrieveTreeNode | %w", err)
	}
	return keyValuePair, err
}

// RetrieveDomainEntry: Retrieve one key-value pair from domain entries table
// Return sql.ErrNoRows if no row is round
func (c *mysqlDB) RetrieveDomainEntry(ctx context.Context, key common.SHA256Output) (*KeyValuePair, error) {
	keyValuePair, err := retrieveOneKeyValuePair(ctx, c.prepGetValueDomainEntries, key)
	if err != nil {
		if err != sql.ErrNoRows {
			return nil, fmt.Errorf("RetrieveDomainEntry | %w", err)
		} else {
			// return sql.ErrNoRows
			return nil, err
		}
	}
	return keyValuePair, nil
}

// RetrieveDomainEntries: Retrieve a list of key-value pairs from domain entries table
// No sql.ErrNoRows will be thrown, if some records does not exist. Check the length of result
// TO_DISCUSS(yongzhe): keep this or move it to updater
func (c *mysqlDB) RetrieveDomainEntries(ctx context.Context, key []common.SHA256Output,
	numOfWorker int) ([]KeyValuePair, error) {
	if len(key) == 0 {
		return nil, nil
	}
	// if work is less than number of worker
	if len(key) < numOfWorker {
		numOfWorker = len(key)
	}

	count := len(key)
	step := count / numOfWorker

	resultChan := make(chan keyValueResult)
	for r := 0; r < numOfWorker-1; r++ {
		go fetchKeyValuePairWorker(resultChan, key[r*step:r*step+step], c.prepGetValueDomainEntries, ctx)
	}
	// let the final one do the rest of the work
	go fetchKeyValuePairWorker(resultChan, key[(numOfWorker-1)*step:count], c.prepGetValueDomainEntries, ctx)

	finishedWorker := 0
	keyValuePairs := make([]KeyValuePair, 0, len(key))

	for numOfWorker > finishedWorker {
		newResult := <-resultChan
		if newResult.Err != nil {
			return nil, fmt.Errorf("RetrieveDomainEntries | %w", newResult.Err)
		}
		keyValuePairs = append(keyValuePairs, newResult.Pairs...)
		finishedWorker++
	}

	return keyValuePairs, nil
}

// ********************************************************************
//                Read functions for updates table
// ********************************************************************
// CountUpdatedDomains: Get number of entries in updates table
func (c *mysqlDB) CountUpdatedDomains(ctx context.Context) (int, error) {
	var number int
	err := c.db.QueryRow("SELECT COUNT(*) FROM updates").Scan(&number)
	if err != nil {
		return 0, fmt.Errorf("CountUpdatedDomains | Scan | %w", err)
	}
	return number, nil
}

// RetrieveUpdatedDomains: Get updated domains name hashes from updates table.
func (c *mysqlDB) RetrieveUpdatedDomains(ctx context.Context, perQueryLimit int) ([]common.SHA256Output, error) {
	count, err := c.CountUpdatedDomains(ctx)
	if err != nil {
		return nil, fmt.Errorf("RetrieveUpdatedDomains | %w", err)
	}

	// calculate the number of workers
	var numberOfWorker int
	if count > perQueryLimit {
		numberOfWorker = count/perQueryLimit + 1
	} else {
		numberOfWorker = 1
	}

	var step int
	if numberOfWorker == 1 {
		step = count
	} else {
		// evenly distribute the workload
		step = count / numberOfWorker
	}

	resultChan := make(chan readKeyResult)
	for r := 0; r < numberOfWorker-1; r++ {
		go fetchKeyWorker(resultChan, r*step, r*step+step, ctx, c.db)
	}
	// let the final one do the rest of the work
	go fetchKeyWorker(resultChan, (numberOfWorker-1)*step, count+1, ctx, c.db)

	finishedWorker := 0
	keys := make([]common.SHA256Output, 0, count)

	// get response
	for numberOfWorker > finishedWorker {
		newResult := <-resultChan
		if newResult.Err != nil {
			return nil, fmt.Errorf("RetrieveUpdatedDomains | %w", newResult.Err)
		}
		keys = append(keys, newResult.Keys...)
		finishedWorker++
	}

	if count != len(keys) {
		return nil, fmt.Errorf("RetrieveUpdatedDomains | incomplete fetching")
	}
	return keys, nil
}

func retrieveOneKeyValuePair(ctx context.Context, stmt *sql.Stmt, key common.SHA256Output) (*KeyValuePair, error) {
	var value []byte
	row := stmt.QueryRow(key[:])
	err := row.Scan(&value)
	return &KeyValuePair{Key: key, Value: value}, err
}
