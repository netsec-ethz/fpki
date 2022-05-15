package logpicker

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"

	_ "github.com/go-sql-driver/mysql"
)

// dbWorker: db worker
type dbWorker struct {
	db               *sql.DB
	inputChan        chan UpdateRequest
	processorPointer *ConsistentDB
}

// start a new db worker
func newWorker(inputChan chan UpdateRequest, processorPointer *ConsistentDB) (*dbWorker, error) {
	db, err := sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/map?maxAllowedPacket=1073741824")
	if err != nil {
		return nil, fmt.Errorf("newWorker | sql.Open | %w", err)
	}
	return &dbWorker{db: db, inputChan: inputChan, processorPointer: processorPointer}, nil
}

// start working
func (worker *dbWorker) work() {
	for {
		// get a new request
		newRequest := <-worker.inputChan
		switch {
		// one log picker thread wants to query some domains; log picker starts to update some domains
		// read (key, value) from db
		case newRequest.RequestType == QueryDomain:
			var querySB strings.Builder
			querySB.WriteString("SELECT `key`,`value`  from `map`.`" + tableName + "` WHERE `key` IN (")
			isFirst := true
			// prepare queries
			for _, v := range newRequest.Domains {
				key := hex.EncodeToString(v[:])
				if isFirst {
					querySB.WriteString("'" + key + "'")
					isFirst = false
				} else {
					querySB.WriteString(",'" + key + "'")
				}
			}
			querySB.WriteString(");")

			// query the data
			mysqlResults, err := worker.db.Query(querySB.String())
			if err != nil {
				newRequest.ReturnChan <- UpdateResult{Err: fmt.Errorf("db.Query | %w", err)}
				continue
			}
			defer mysqlResults.Close()

			result := UpdateResult{
				FetchedDomainsName:    [][32]byte{},
				FetchedDomainsContent: [][]byte{},
			}

			var domain string
			var value string

			for mysqlResults.Next() {
				err := mysqlResults.Scan(&domain, &value)
				if err != nil {
					newRequest.ReturnChan <- UpdateResult{Err: fmt.Errorf("Scan | %w", err)}
					continue
				}
				domainBytes, err := hex.DecodeString(domain)
				if err != nil {
					newRequest.ReturnChan <- UpdateResult{Err: fmt.Errorf("DecodeString domain | %w", err)}
					continue
				}

				valueBytes := []byte(value)

				// size of the hash must be 32 bytes
				if len(domainBytes) != 32 {
					newRequest.ReturnChan <- UpdateResult{Err: fmt.Errorf("size of the hash is not 32 bytes.")}
					continue
				}

				var domainBytesCopy [32]byte
				copy(domainBytesCopy[:], domainBytes)

				result.FetchedDomainsName = append(result.FetchedDomainsName, domainBytesCopy)
				result.FetchedDomainsContent = append(result.FetchedDomainsContent, valueBytes)
			}
			newRequest.ReturnChan <- result

		// log picker thread wants to store data to db
		case newRequest.RequestType == UpdateDomain:
			var insertSB strings.Builder

			queryStr := "REPLACE into `map`.`" + tableName + "` (`key`, `value`) values "
			insertSB.WriteString(queryStr)

			isFirst := true

			for i, v := range newRequest.UpdatedDomainName {
				if isFirst {
					insertSB.WriteString("('" + v + "', '" + newRequest.UpdatedDomainContent[i] + "')")
					isFirst = false
				} else {
					insertSB.WriteString(",('" + v + "', '" + newRequest.UpdatedDomainContent[i] + "')")
				}
			}
			insertSB.WriteString(";")

			_, err := worker.db.Exec(insertSB.String())
			// unlock the cooresponding domains
			worker.processorPointer.unlockDomain(newRequest.Domains)
			if err != nil {
				newRequest.ReturnChan <- UpdateResult{Err: fmt.Errorf(" db.Exec | %w", err)}
			} else {
				newRequest.ReturnChan <- UpdateResult{}
			}
		}
	}

}
