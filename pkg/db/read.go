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
func (c *mysqlDB) RetrieveTreeNode(ctx context.Context, key common.SHA256Output) ([]byte, error) {
	value, err := retrieveValue(ctx, c.prepGetValueTree, key)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("RetrieveTreeNode | %w", err)
	}
	return value, err
}

// RetrieveDomainEntry: Retrieve one key-value pair from domain entries table
// Return sql.ErrNoRows if no row is round
func (c *mysqlDB) RetrieveDomainEntry(ctx context.Context, key common.SHA256Output) (
	[]byte, error) {

	keyValuePair, err := retrieveValue(ctx, c.prepGetValueDomainEntries, key)
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
func (c *mysqlDB) RetrieveDomainEntries(ctx context.Context, key []common.SHA256Output) (
	[]*KeyValuePair, error) {

	return c.retrieveDomainEntries(ctx, key)
}

// used for retrieving key value pair
func (c *mysqlDB) retrieveDomainEntries(ctx context.Context, keys []common.SHA256Output) (
	[]*KeyValuePair, error) {
	str := "SELECT `key`, `value` FROM domainEntries WHERE `key` IN " + repeatStmt(1, len(keys))
	args := make([]interface{}, len(keys))
	for i, k := range keys {
		k := k         // XXX(juagargi): create a copy
		args[i] = k[:] // assign the slice covering the copy (the original k changes !!)
	}
	rows, err := c.db.QueryContext(ctx, str, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var k, v []byte
	domainEntries := make([]*KeyValuePair, 0, len(keys))
	for rows.Next() {
		if err = rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		domainEntries = append(domainEntries, &KeyValuePair{
			Key:   *(*common.SHA256Output)(k),
			Value: v,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	//if len(domainEntries) != len(keys) {
	//	fmt.Println("incomplete fetching")
	//	fmt.Println(len(domainEntries), "  ", len(keys))
	//}
	return domainEntries, nil
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

func retrieveValue(ctx context.Context, stmt *sql.Stmt, key common.SHA256Output) ([]byte, error) {
	var value []byte
	row := stmt.QueryRow(key[:])
	err := row.Scan(&value)
	return value, err
}
