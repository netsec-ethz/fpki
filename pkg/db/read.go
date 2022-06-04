package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

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

// ********************************************************************
//                Read functions for updates table
// ********************************************************************
// GetCountOfUpdatesDomainsUpdates: Get number of entries in updates table
func (c *mysqlDB) GetCountOfUpdatesDomainsUpdates(ctx context.Context) (int, error) {
	var number int
	err := c.db.QueryRow("SELECT COUNT(*) FROM updates").Scan(&number)
	if err != nil {
		return 0, fmt.Errorf("GetCountOfUpdatesDomainsUpdates | Scan | %w", err)
	}
	return number, nil
}

// RetrieveUpdatedDomainHashesUpdates: Get updated domains name hashes from updates table. The updates table will be truncated.
func (c *mysqlDB) RetrieveUpdatedDomainHashesUpdates(ctx context.Context, perQueryLimit int) ([]common.SHA256Output, error) {
	count, err := c.GetCountOfUpdatesDomainsUpdates(ctx)
	if err != nil {
		return nil, fmt.Errorf("RetrieveUpdatedDomainHashesUpdates | RetrieveTableRowsCount | %w", err)
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
			return nil, fmt.Errorf("RetrieveUpdatedDomainHashesUpdates | %w", newResult.Err)
		}
		keys = append(keys, newResult.Keys...)
		finishedWorker++
	}

	if count != len(keys) {
		return nil, fmt.Errorf("RetrieveUpdatedDomainHashesUpdates | incomplete fetching")
	}

	err = c.TruncateUpdatesTableUpdates(ctx)
	if err != nil {
		return nil, fmt.Errorf("RetrieveUpdatedDomainHashesUpdates | TruncateUpdatesTableUpdates | %w", err)
	}

	return keys, nil
}

// ********************************************************************
//                             Common
// ********************************************************************

func retrieveOneKeyValuePair(ctx context.Context, stmt *sql.Stmt, key common.SHA256Output) (*KeyValuePair, error) {
	var value []byte
	start := time.Now()
	result := stmt.QueryRow(key[:])
	end := time.Now()
	fmt.Println(end.Sub(start))
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
