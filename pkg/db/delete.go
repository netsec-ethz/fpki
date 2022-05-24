package db

import (
	"context"
	"database/sql"
	"fmt"
)

func (c *mysqlDB) DeleteKeyValuePairBatches(ctx context.Context, keys []string, tableName TableName) error {
	dataLen := len(keys)
	remainingDataLen := dataLen

	var stmt *sql.Stmt
	var tableNameString string
	switch {
	case tableName == DomainEntries:
		stmt = c.prepDeleteKeyValueDomainEntries
		tableNameString = "domainEntries"
	case tableName == Tree:
		stmt = c.prepDeleteKeyValueTree
		tableNameString = "tree"
	default:
		return fmt.Errorf("DeleteKeyValuePairBatches : Table name not supported")
	}

	// write in batch of 1000
	for i := 0; i*1000 <= dataLen-1000; i++ {
		data := make([]interface{}, 1000)

		for j := 0; j < 1000; j++ {
			data[j] = keys[i*1000+j]
		}

		_, err := stmt.Exec(data...)
		if err != nil {
			return fmt.Errorf("DeleteKeyValuePairBatches | Exec | %w", err)
		}
		remainingDataLen = remainingDataLen - 1000
	}

	// if remaining data is less than 1000
	if remainingDataLen > 0 {
		// insert updated domains' entries
		repeatedStmt := repeatStmtForDelete(tableNameString, remainingDataLen)
		stmt, err := c.db.Prepare(repeatedStmt)
		if err != nil {
			return fmt.Errorf("DeleteKeyValuePairBatches | db.Prepare | %w", err)
		}
		data := make([]interface{}, remainingDataLen)

		for j := 0; j < remainingDataLen; j++ {
			data[j] = keys[dataLen-remainingDataLen+j]
		}
		_, err = stmt.Exec(data...)
		if err != nil {
			return fmt.Errorf("DeleteKeyValuePairBatches | Exec remaining | %w", err)
		}
		stmt.Close()
	}
	return nil
}

func (c *mysqlDB) TruncateUpdatesTable(ctx context.Context) error {
	_, err := c.db.Exec("TRUNCATE `fpki`.`updates`;")
	if err != nil {
		return fmt.Errorf("TruncateUpdatesTable | TRUNCATE | %w", err)
	}
	return nil
}
