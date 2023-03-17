package db

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/netsec-ethz/fpki/pkg/common"
)

func (c *mysqlDB) UpdateDomainEntries(ctx context.Context, pairs []*KeyValuePair) (int, error) {
	panic("not available")
}

// UpdateDomainEntries: Update a list of key-value store
func (c *mysqlDB) UpdateDomainEntriesOLD(ctx context.Context, keyValuePairs []*KeyValuePair) (int, error) {
	numOfUpdatedRecords, err := c.doUpdatePairs(ctx, keyValuePairs, c.getDomainEntriesUpdateStmts)
	if err != nil {
		return 0, fmt.Errorf("UpdateDomainEntries | %w", err)
	}
	return numOfUpdatedRecords, nil
}

func (c *mysqlDB) DeleteTreeNodes(ctx context.Context, keys []common.SHA256Output) (int, error) {
	str := "DELETE FROM tree WHERE key32 IN " + repeatStmt(1, len(keys))
	params := make([]interface{}, len(keys))
	for i, k := range keys {
		params[i] = k[:]
	}
	res, err := c.db.ExecContext(ctx, str, params...)
	if err != nil {
		return 0, fmt.Errorf("error deleting keys from tree: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		panic(fmt.Errorf("unsupported retrieving number of rows affected: %w", err))
	}
	return int(n), nil
}

// DeleteTreeNodes  deletes a list of key-value stored in the tree table.
func (c *mysqlDB) DeleteTreeNodesOLD(ctx context.Context, keys []common.SHA256Output) (int, error) {
	n, err := c.doUpdateKeys(ctx, keys, c.getTreeDeleteStmts)
	if err != nil {
		return 0, fmt.Errorf("DeleteTreeNodes | %w", err)
	}

	return n, nil
}

func (c *mysqlDB) UpdateTreeNodes(ctx context.Context, keyValuePairs []*KeyValuePair) (int, error) {
	if len(keyValuePairs) == 0 {
		return 0, nil
	}
	str := "REPLACE INTO tree (key32,value) VALUES " + repeatStmt(len(keyValuePairs), 2)
	params := make([]interface{}, 2*len(keyValuePairs))
	for i, pair := range keyValuePairs {
		params[i*2] = pair.Key[:]
		params[i*2+1] = pair.Value
	}
	res, err := c.db.ExecContext(ctx, str, params...)
	if err != nil {
		return 0, fmt.Errorf("error inserting key-values into tree: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		panic(fmt.Errorf("unsupported retrieving number of rows affected: %w", err))
	}
	return int(n), nil
}

// UpdateTreeNodes: Update a list of key-value store
func (c *mysqlDB) UpdateTreeNodesOLD(ctx context.Context, keyValuePairs []*KeyValuePair) (int, error) {
	numOfUpdatedPairs, err := c.doUpdatePairs(ctx, keyValuePairs, c.getTreeStructureUpdateStmts)
	if err != nil {
		return 0, fmt.Errorf("UpdateTreeNodes | %w", err)
	}
	return numOfUpdatedPairs, nil
}

// AddUpdatedDomains inserts a list of keys into the updates table.
// If a key exists, ignores it.
func (c *mysqlDB) AddUpdatedDomains(ctx context.Context, keys []common.SHA256Output) (int, error) {
	n, err := c.doUpdateKeys(ctx, keys, c.getUpdatesInsertStmts)
	if err != nil {
		return 0, fmt.Errorf("AddUpdatedDomains | %w", err)
	}
	return n, nil
}

// RemoveAllUpdatedDomains: truncate updates table
func (c *mysqlDB) RemoveAllUpdatedDomains(ctx context.Context) error {
	_, err := c.db.Exec("TRUNCATE `fpki`.`updates`;")
	if err != nil {
		return fmt.Errorf("RemoveAllUpdatedDomains | TRUNCATE | %w", err)
	}
	return nil
}

func (c *mysqlDB) SaveRoot(ctx context.Context, root *common.SHA256Output) error {
	str := "REPLACE INTO root (key32) VALUES (?)"
	_, err := c.db.ExecContext(ctx, str, (*root)[:])
	if err != nil {
		return fmt.Errorf("error inserting root ID: %w", err)
	}
	return nil
}

// ********************************************************************
//
//	Common
//
// ********************************************************************
// worker to update key-value pairs
func (c *mysqlDB) doUpdatePairs(ctx context.Context, keyValuePairs []*KeyValuePair,
	stmtGetter prepStmtGetter) (int, error) {

	dataLen := len(keyValuePairs)
	affectedRowsCount := 0

	data := make([]interface{}, 2*batchSize) // 2 elements per record
	// updateFcn updates the DB using keyValuePairs starting at index/batch, until the end of the
	// batch or the end of keyValuePairs
	updateFcn := func(stmt *sql.Stmt, index int) (int, error) {
		data := data[:2*min(batchSize, dataLen-batchSize*index)]
		for j := 0; j < len(data)/2; j++ {
			data[2*j] = keyValuePairs[index*batchSize+j].Key[:]
			data[2*j+1] = keyValuePairs[index*batchSize+j].Value
		}
		result, err := stmt.Exec(data...)
		if err != nil {
			return 0, fmt.Errorf("updateFcn | Exec | %w", err)
		}
		n, err := result.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("updateFcn | RowsAffected | %w", err)
		}
		return int(n), nil
	}

	updateWholeBatchStmt, updatePartialBatchStmt := stmtGetter(dataLen % batchSize)
	for i := 0; i < dataLen/batchSize; i++ {
		n, err := updateFcn(updateWholeBatchStmt, i)
		if err != nil {
			return 0, fmt.Errorf("doUpdatePairs | wholeBatch | %w", err)
		}
		affectedRowsCount += n
	}
	if dataLen%batchSize > 0 {
		n, err := updateFcn(updatePartialBatchStmt, dataLen/batchSize)
		if err != nil {
			return 0, fmt.Errorf("doUpdatePairs | partialBatch | %w", err)
		}
		affectedRowsCount += n
	}
	//defer updateWholeBatchStmt.Close()
	//defer updatePartialBatchStmt.Close()
	return affectedRowsCount, nil
}

// worker to update keys
func (c *mysqlDB) doUpdateKeys(ctx context.Context, keys []common.SHA256Output,
	stmtGetter prepStmtGetter) (int, error) {

	dataLen := len(keys)
	affectedRowsCount := 0

	if dataLen == 0 {
		return 0, nil
	}

	data := make([]interface{}, batchSize)
	// updateFcn updates the DB using keys starting at index/batch, until the end of the
	// batch or the end of keyValuePairs
	updateFcn := func(stmt *sql.Stmt, index int) (int, error) {
		data := data[:min(batchSize, dataLen-batchSize*index)]
		for j := 0; j < len(data); j++ {
			data[j] = keys[index*batchSize+j][:]
		}
		result, err := stmt.Exec(data...)
		if err != nil {
			return 0, fmt.Errorf("updateFcn | Exec | %w", err)
		}
		n, err := result.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("updateFcn | RowsAffected | %w", err)
		}
		return int(n), nil
	}

	updateWholeBatchStmt, updatePartialBatchStmt := stmtGetter(dataLen % batchSize)
	for i := 0; i < dataLen/batchSize; i++ {
		n, err := updateFcn(updateWholeBatchStmt, i)
		if err != nil {
			return 0, fmt.Errorf("doUpdateKeys | wholeBatch | %w", err)
		}
		affectedRowsCount += n
	}
	if dataLen%batchSize > 0 {
		n, err := updateFcn(updatePartialBatchStmt, dataLen/batchSize)
		if err != nil {
			return 0, fmt.Errorf("doUpdateKeys | partialBatch | %w", err)
		}
		affectedRowsCount += n
	}
	return affectedRowsCount, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
