package db

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	//"time"
)

// used during main thread and worker thread
type readKeyResult struct {
	Keys []DomainHash
	Err  error
}

// RetrieveOneKeyValuePair: Retrieve one single key-value pair
func (c *mysqlDB) RetrieveOneKeyValuePair_TreeStruc(ctx context.Context, key DomainHash) (*KeyValuePair, error) {
	var value []byte
	stmt := c.prepGetValueTree

	result := stmt.QueryRow(key[:])

	err := result.Scan(&value)
	if err != nil {
		switch {
		case err != sql.ErrNoRows:
			return nil, fmt.Errorf("RetrieveOneKeyValuePair | Scan |%w", err)
		case err == sql.ErrNoRows:
			return nil, nil
		}
	}

	return &KeyValuePair{Key: key, Value: value}, nil
}

// RetrieveKeyValuePairFromTreeStruc: Retrieve a list of key-value pairs from DB. Multi-threaded
func (c *mysqlDB) RetrieveKeyValuePair_TreeStruc(ctx context.Context, key []DomainHash, numOfWorker int) ([]KeyValuePair, error) {
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

func (c *mysqlDB) RetrieveKeyValuePair_DomainEntries(ctx context.Context, key []DomainHash, numOfWorker int) ([]KeyValuePair, error) {
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

func fetchKeyValuePairWorker(resultChan chan keyValueResult, keys []DomainHash, stmt *sql.Stmt, ctx context.Context) {
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

// RetrieveUpdatedDomainHashes: Get updated domains name hashes from updates table
func (c *mysqlDB) RetrieveUpdatedDomainHashes_Updates(ctx context.Context, perQueryLimit int) ([]DomainHash, error) {
	count, err := c.GetCountOfUpdatesDomains_Updates(ctx)
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
	keys := []DomainHash{}

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

	err = c.TruncateUpdatesTable_Updates(ctx)
	if err != nil {
		return nil, fmt.Errorf("RetrieveUpdatedDomainHashes_Updates | TruncateUpdatesTable | %w", err)
	}

	return keys, nil
}

func fetchKeyWorker(resultChan chan readKeyResult, start, end int, ctx context.Context, db *sql.DB) {
	var key DomainHash
	result := []DomainHash{}

	stmt, err := db.Prepare("SELECT * FROM updates LIMIT " + strconv.Itoa(start) + "," + strconv.Itoa(end-start))
	if err != nil {
		resultChan <- readKeyResult{Err: fmt.Errorf("fetchKeyWorker | SELECT * | %w", err)}
	}
	resultRows, err := stmt.Query()
	if err != nil {
		resultChan <- readKeyResult{Err: fmt.Errorf("fetchKeyWorker | Query | %w", err)}
	}
	defer resultRows.Close()
	for resultRows.Next() {
		err = resultRows.Scan(&key)
		if err != nil {
			resultChan <- readKeyResult{Err: fmt.Errorf("fetchKeyWorker | Scan | %w", err)}
		}
		result = append(result, key)
	}
	stmt.Close()

	resultChan <- readKeyResult{Keys: result}
}

// CountUpdates: Get number of entries in updates table
func (c *mysqlDB) GetCountOfUpdatesDomains_Updates(ctx context.Context) (int, error) {
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
