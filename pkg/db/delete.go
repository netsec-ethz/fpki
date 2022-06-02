package db

import (
	"context"
	"fmt"
)

// DeleteKeyValues: Delete a list of key-value store
func (c *mysqlDB) DeleteKeyValues_TreeStruc(ctx context.Context, keys []string) error {
	dataLen := len(keys)
	remainingDataLen := dataLen

	// parse the prepared statement and table name
	stmt := c.prepDeleteKeyValueTree

	// write in batch of batchSize
	for i := 0; i*batchSize <= dataLen-batchSize; i++ {
		data := make([]interface{}, batchSize)

		for j := 0; j < batchSize; j++ {
			data[j] = keys[i*batchSize+j]
		}

		_, err := stmt.Exec(data...)
		if err != nil {
			return fmt.Errorf("DeleteKeyValues | Exec | %w", err)
		}
		remainingDataLen = remainingDataLen - batchSize
	}

	// if remaining data is less than batchSize, finish the remaining deleting
	if remainingDataLen > 0 {
		// insert updated domains' entries
		repeatedStmt := repeatStmtForDelete("tree", remainingDataLen)
		stmt, err := c.db.Prepare(repeatedStmt)
		if err != nil {
			return fmt.Errorf("DeleteKeyValues | db.Prepare | %w", err)
		}
		data := make([]interface{}, remainingDataLen)

		for j := 0; j < remainingDataLen; j++ {
			data[j] = keys[dataLen-remainingDataLen+j]
		}
		_, err = stmt.Exec(data...)
		if err != nil {
			return fmt.Errorf("DeleteKeyValues | Exec remaining | %w", err)
		}
		stmt.Close()
	}
	return nil
}

// TruncateUpdatesTable: truncate updates table
func (c *mysqlDB) TruncateUpdatesTable_Updates(ctx context.Context) error {
	_, err := c.db.Exec("TRUNCATE `fpki`.`updates`;")
	if err != nil {
		return fmt.Errorf("TruncateUpdatesTable | TRUNCATE | %w", err)
	}
	return nil
}
