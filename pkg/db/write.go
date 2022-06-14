package db

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/netsec-ethz/fpki/pkg/common"
)

// ********************************************************************
//                Write functions for Tree table
// ********************************************************************

// UpdateKeyValuesDomainEntries: Update a list of key-value store
func (c *mysqlDB) UpdateKeyValuesDomainEntries(ctx context.Context, keyValuePairs []KeyValuePair) (int64, error) {
	numOfUpdatedRecords, err := c.doUpdatesPairs(ctx, c.prepUpdateValueDomainEntries, keyValuePairs, DomainEntries)
	if err != nil {
		return 0, fmt.Errorf("UpdateKeyValuesDomainEntries | %w", err)
	}
	return numOfUpdatedRecords, nil
}

// DeleteKeyValuesTreeStruc: Delete a list of key-value store
func (c *mysqlDB) DeleteKeyValuesTreeStruct(ctx context.Context, keys []common.SHA256Output) (int64, error) {
	numOfDeletedRecords, err := c.doUpdatesKeys(ctx, c.prepDeleteKeyValueTree, keys, Tree)
	if err != nil {
		return 0, fmt.Errorf("DeleteKeyValuesTreeStruc | %w", err)
	}

	return numOfDeletedRecords, nil
}

// ********************************************************************
//                Write functions for domain entries table
// ********************************************************************

// UpdateKeyValuesTreeStruct: Update a list of key-value store
func (c *mysqlDB) UpdateKeyValuesTreeStruct(ctx context.Context, keyValuePairs []KeyValuePair) (int64, error) {
	numOfUpdatedPairs, err := c.doUpdatesPairs(ctx, c.prepUpdateValueTree, keyValuePairs, Tree)
	if err != nil {
		return 0, fmt.Errorf("UpdateKeyValuesTreeStruc | %w", err)
	}
	return numOfUpdatedPairs, nil
}

// ********************************************************************
//                Write functions for updates table
// ********************************************************************

// AddUpdatedDomainHashesUpdates: Insert a list of keys into the updates table. If key exists, ignore it.
func (c *mysqlDB) AddUpdatedDomainHashesUpdates(ctx context.Context, keys []common.SHA256Output) (int64, error) {
	numOfUpdatedPairs, err := c.doUpdatesKeys(ctx, c.prepInsertKeysUpdates, keys, Updates)
	if err != nil {
		return 0, fmt.Errorf("AddUpdatedDomainHashesUpdates | %w", err)
	}
	return numOfUpdatedPairs, nil
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
func (c *mysqlDB) doUpdatesPairs(ctx context.Context, stmt *sql.Stmt, keyValuePairs []KeyValuePair, tableName tableName) (int64, error) {
	dataLen := len(keyValuePairs)
	var affectedRowsCount int64
	affectedRowsCount = 0

	// write in batch of batchSize
	for i := 0; i < dataLen/batchSize; i++ {
		data := make([]interface{}, 2*batchSize) // 2 elements per record ()

		for j := 0; j < batchSize; j++ {
			data[2*j] = keyValuePairs[i*batchSize+j].Key[:]
			data[2*j+1] = keyValuePairs[i*batchSize+j].Value
		}

		result, err := stmt.Exec(data...)
		if err != nil {
			return 0, fmt.Errorf("doUpdatesPairs | Exec | %w", err)
		}

		numOfRows, err := result.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("doUpdatesKeys | RowsAffected | %w", err)
		}

		affectedRowsCount = affectedRowsCount + numOfRows
	}

	// if remaining data is less than batchSize
	if dataLen%batchSize > 0 {
		var repeatedStmt string
		// prepare new stmt according to table name
		switch tableName {
		case Tree:
			repeatedStmt = "REPLACE into tree (`key`, `value`) values " + repeatStmt(dataLen%batchSize, 2)
		case DomainEntries:
			repeatedStmt = "REPLACE into domainEntries (`key`, `value`) values " + repeatStmt(dataLen%batchSize, 2)
		}

		// prepare data
		data := make([]interface{}, 2*(dataLen%batchSize)) // 2 elements per record ()

		for j := 0; j < dataLen%batchSize; j++ {
			data[2*j] = keyValuePairs[dataLen-dataLen%batchSize+j].Key[:]
			data[2*j+1] = keyValuePairs[dataLen-dataLen%batchSize+j].Value
		}

		result, err := c.db.Exec(repeatedStmt, data...)
		if err != nil {
			return 0, fmt.Errorf("doUpdatesPairs | Exec remaining | %w", err)
		}

		numOfRows, err := result.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("doUpdatesKeys | RowsAffected | %w", err)
		}

		affectedRowsCount = affectedRowsCount + numOfRows
	}
	return affectedRowsCount, nil
}

// worker to update keys
func (c *mysqlDB) doUpdatesKeys(ctx context.Context, stmt *sql.Stmt, keys []common.SHA256Output, tableName tableName) (int64,
	error) {
	dataLen := len(keys)
	var affectedRowsCount int64
	affectedRowsCount = 0

	// write in batch of batchSize
	for i := 0; i < dataLen/batchSize; i++ {
		data := make([]interface{}, batchSize)

		for j := 0; j < batchSize; j++ {
			data[j] = keys[i*batchSize+j][:]
		}

		result, err := stmt.Exec(data...)
		if err != nil {
			return 0, fmt.Errorf("doUpdatesKeys | Exec | %w", err)
		}

		numOfRows, err := result.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("doUpdatesKeys | RowsAffected | %w", err)
		}

		affectedRowsCount = affectedRowsCount + numOfRows
	}

	// if remaining data is less than batchSize, finish the remaining deleting
	if dataLen%batchSize > 0 {
		// prepare new stmt according to table name
		var repeatedStmt string
		switch tableName {
		case Tree:
			repeatedStmt = repeatStmtForDelete("tree", dataLen%batchSize)
		case Updates:
			repeatedStmt = "INSERT IGNORE into `updates` (`key`) VALUES " + repeatStmt(dataLen%batchSize, 1)
		}

		// prepare data
		data := make([]interface{}, dataLen%batchSize)

		for j := 0; j < dataLen%batchSize; j++ {
			data[j] = keys[dataLen-dataLen%batchSize+j][:]
		}

		result, err := c.db.Exec(repeatedStmt, data...)
		if err != nil {
			return 0, fmt.Errorf("doUpdatesKeys | Exec remaining | %w", err)
		}

		numOfRows, err := result.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("doUpdatesKeys | RowsAffected | %w", err)
		}

		affectedRowsCount = affectedRowsCount + numOfRows
	}
	return affectedRowsCount, nil
}
