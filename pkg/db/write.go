package db

import (
	"context"
	"fmt"

	"github.com/netsec-ethz/fpki/pkg/common"
)

// UpdateKeyValues_DomainEntries: Update a list of key-value store
func (c *mysqlDB) UpdateKeyValuesDomainEntries(ctx context.Context, keyValuePairs []KeyValuePair) (error, int) {
	dataLen := len(keyValuePairs)
	remainingDataLen := dataLen

	stmt := c.prepUpdateValueDomainEntries

	// write in batch of batchSize
	for i := 0; i*batchSize <= dataLen-batchSize; i++ {
		data := make([]interface{}, 2*batchSize) // 2 elements per record ()

		for j := 0; j < batchSize; j++ {

			//data[2*j] = keyValuePairs[i*batchSize+j].Key
			data[2*j] = keyValuePairs[i*batchSize+j].Key[:]
			data[2*j+1] = keyValuePairs[i*batchSize+j].Value
		}
		_, err := stmt.Exec(data...)
		if err != nil {
			return fmt.Errorf("UpdateKeyValuePairBatches | Exec | %w", err), 0
		}

		remainingDataLen = remainingDataLen - batchSize
	}

	// if remaining data is less than batchSize
	if remainingDataLen > 0 {
		// insert updated domains' entries
		repeatedStmt := "REPLACE into domainEntries (`key`, `value`) values " + repeatStmt(remainingDataLen, 2)
		stmt, err := c.db.Prepare(repeatedStmt)
		if err != nil {
			return fmt.Errorf("UpdateKeyValuePairBatches | db.Prepare | %w", err), 0
		}
		data := make([]interface{}, 2*remainingDataLen) // 2 elements per record ()

		for j := 0; j < remainingDataLen; j++ {
			data[2*j] = keyValuePairs[dataLen-remainingDataLen+j].Key[:]
			data[2*j+1] = keyValuePairs[dataLen-remainingDataLen+j].Value
		}
		_, err = stmt.Exec(data...)
		if err != nil {
			return fmt.Errorf("UpdateKeyValuePairBatches | Exec remaining | %w", err), 0
		}
		stmt.Close()
	}
	return nil, dataLen
}

// UpdateKeyValues_TreeStruc: Update a list of key-value store
func (c *mysqlDB) UpdateKeyValuesTreeStruc(ctx context.Context, keyValuePairs []KeyValuePair) (error, int) {
	dataLen := len(keyValuePairs)
	remainingDataLen := dataLen

	stmt := c.prepUpdateValueTree

	// write in batch of batchSize
	for i := 0; i*batchSize <= dataLen-batchSize; i++ {
		data := make([]interface{}, 2*batchSize) // 2 elements per record ()

		for j := 0; j < batchSize; j++ {
			data[2*j] = keyValuePairs[i*batchSize+j].Key[:]
			data[2*j+1] = keyValuePairs[i*batchSize+j].Value
		}
		_, err := stmt.Exec(data...)
		if err != nil {
			return fmt.Errorf("UpdateKeyValuePairBatches | Exec | %w", err), 0
		}

		remainingDataLen = remainingDataLen - batchSize
	}

	// if remaining data is less than batchSize
	if remainingDataLen > 0 {
		// insert updated domains' entries
		repeatedStmt := "REPLACE into tree (`key`, `value`) values " + repeatStmt(remainingDataLen, 2)
		stmt, err := c.db.Prepare(repeatedStmt)
		if err != nil {
			return fmt.Errorf("UpdateKeyValuePairBatches | db.Prepare | %w", err), 0
		}
		data := make([]interface{}, 2*remainingDataLen) // 2 elements per record ()

		for j := 0; j < remainingDataLen; j++ {
			data[2*j] = keyValuePairs[dataLen-remainingDataLen+j].Key[:]
			data[2*j+1] = keyValuePairs[dataLen-remainingDataLen+j].Value
		}
		_, err = stmt.Exec(data...)
		if err != nil {
			return fmt.Errorf("UpdateKeyValuePairBatches | Exec | %w", err), 0
		}
		stmt.Close()
	}
	return nil, dataLen
}

// InsertIgnoreKeyBatches: Insert a list of keys into the updates table. If key exists, ignore it.
func (c *mysqlDB) AddUpdatedDomainHashesUpdates(ctx context.Context, keys []common.SHA256Output) (int, error) {
	dataLen := len(keys)
	remainingDataLen := dataLen

	stmt := c.prepInsertKeysUpdates

	// write in batch of batchSize
	for i := 0; i*batchSize <= dataLen-batchSize; i++ {
		data := make([]interface{}, batchSize) // 2 elements per record ()

		for j := 0; j < batchSize; j++ {
			data[j] = keys[i*batchSize+j][:]
		}

		_, err := stmt.Exec(data...)
		if err != nil {
			return 0, fmt.Errorf("ReplaceKeys | Exec | %w", err)
		}

		remainingDataLen = remainingDataLen - batchSize
	}

	// if remaining data is less than batchSize
	if remainingDataLen > 0 {
		// insert updated domains' entries
		stmt, err := c.db.Prepare("INSERT IGNORE into `updates` (`key`) VALUES " + repeatStmt(remainingDataLen, 1))
		if err != nil {
			return 0, fmt.Errorf("ReplaceKeys | db.Prepare | %w", err)
		}
		data := make([]interface{}, remainingDataLen) // 2 elements per record ()

		for j := 0; j < remainingDataLen; j++ {
			data[j] = keys[dataLen-remainingDataLen+j][:]
		}

		_, err = stmt.Exec(data...)
		if err != nil {
			return 0, fmt.Errorf("ReplaceKeys | Exec | %w", err)
		}
		stmt.Close()
	}
	return dataLen, nil
}
