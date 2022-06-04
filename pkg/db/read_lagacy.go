package db

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/netsec-ethz/fpki/pkg/common"
)

// TODO(yongzhe): delete this file. move multi-thread reading to responder

// RetrieveKeyValuePairTreeStruc: Retrieve a list of key-value pairs from DB. Multi-threaded
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
			return nil, fmt.Errorf("RetrieveKeyValuePairTreeStruc | %w", newResult.Err)
		}
		keyValuePairs = append(keyValuePairs, newResult.Pairs...)
		finishedWorker++
	}

	return keyValuePairs, nil
}

// RetrieveKeyValuePairDomainEntries: Retrieve a list of key-value pairs from domain entries table
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
			return nil, fmt.Errorf("RetrieveKeyValuePairDomainEntries | %w", newResult.Err)
		}
		keyValuePairs = append(keyValuePairs, newResult.Pairs...)
		finishedWorker++
	}

	return keyValuePairs, nil
}

func fetchKeyValuePairWorker(resultChan chan keyValueResult, keys []common.SHA256Output, stmt *sql.Stmt, ctx context.Context) {
	numOfWork := len(keys)
	pairs := []KeyValuePair{}
	var value []byte

work_loop:
	for i := 0; i < numOfWork; i++ {
		result := stmt.QueryRow(keys[i][:])
		err := result.Scan(&value)
		if err != nil {
			switch {
			case err != sql.ErrNoRows:
				resultChan <- keyValueResult{Err: fmt.Errorf("fetchKeyValuePairWorker | result.Scan | %w", err)}
				return
			case err == sql.ErrNoRows:
				continue work_loop
			}
		}
		pairs = append(pairs, KeyValuePair{Key: keys[i], Value: value})
	}

	resultChan <- keyValueResult{Pairs: pairs}
}
