package db

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"

	"github.com/netsec-ethz/fpki/pkg/common"
)

func fetchKeyWorker(resultChan chan readKeyResult, start, end int, ctx context.Context, db *sql.DB) {
	var key []byte
	result := []common.SHA256Output{}

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
		var key32bytes common.SHA256Output
		copy(key32bytes[:], key)
		result = append(result, key32bytes)
	}
	stmt.Close()

	resultChan <- readKeyResult{Keys: result}
}

func fetchKeyValuePairWorker(resultChan chan keyValueResult, keys []common.SHA256Output, stmt *sql.Stmt, ctx context.Context) {
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
