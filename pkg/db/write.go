package db

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/netsec-ethz/fpki/pkg/common"
)

// UpdateKeyValuesDomainEntries: Update a list of key-value store
func (c *mysqlDB) UpdateKeyValuesDomainEntries(ctx context.Context, keyValuePairs []KeyValuePair) (int, error) {
	numOfUpdatedRecords, err := c.doUpdatePairs(ctx, keyValuePairs, c.getDomainEntriesUpdateStmts)
	if err != nil {
		return 0, fmt.Errorf("UpdateKeyValuesDomainEntries | %w", err)
	}
	return numOfUpdatedRecords, nil
}

// DeleteKeyValuesTreeStruct  deletes a list of key-value stored in the tree table.
func (c *mysqlDB) DeleteKeyValuesTreeStruct(ctx context.Context, keys []common.SHA256Output) (int, error) {
	n, err := c.doUpdateKeys(ctx, keys, c.getTreeDeleteStmts)
	if err != nil {
		return 0, fmt.Errorf("DeleteKeyValuesTreeStruct | %w", err)
	}

	return n, nil
}

// UpdateKeyValuesTreeStruct: Update a list of key-value store
func (c *mysqlDB) UpdateKeyValuesTreeStruct(ctx context.Context, keyValuePairs []KeyValuePair) (int, error) {
	numOfUpdatedPairs, err := c.doUpdatePairs(ctx, keyValuePairs, c.getTreeStructureUpdateStmts)
	if err != nil {
		return 0, fmt.Errorf("UpdateKeyValuesTreeStruc | %w", err)
	}
	return numOfUpdatedPairs, nil
}

// AddUpdatedDomainHashesUpdates inserts a list of keys into the updates table.
// If a key exists, ignores it.
func (c *mysqlDB) AddUpdatedDomainHashesUpdates(ctx context.Context, keys []common.SHA256Output) (int, error) {
	n, err := c.doUpdateKeys(ctx, keys, c.getUpdatesInsertStmts)
	if err != nil {
		return 0, fmt.Errorf("AddUpdatedDomainHashesUpdates | %w", err)
	}
	return n, nil
}

// TruncateUpdatesTableUpdates: truncate updates table
func (c *mysqlDB) TruncateUpdatesTableUpdates(ctx context.Context) error {
	_, err := c.db.Exec("TRUNCATE `fpki`.`updates`;")
	if err != nil {
		return fmt.Errorf("TruncateUpdatesTableUpdates | TRUNCATE | %w", err)
	}
	return nil
}

// ********************************************************************
//                              Common
// ********************************************************************
// worker to update key-value pairs
func (c *mysqlDB) doUpdatePairs(ctx context.Context, keyValuePairs []KeyValuePair,
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
	return affectedRowsCount, nil
}

// worker to update keys
func (c *mysqlDB) doUpdateKeys(ctx context.Context, keys []common.SHA256Output,
	stmtGetter prepStmtGetter) (int, error) {

	dataLen := len(keys)
	affectedRowsCount := 0

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
