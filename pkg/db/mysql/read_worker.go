package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
)

// keyValueResult: used in worker thread; in multi-thread read
type keyValueResult struct {
	Pairs []*db.KeyValuePair
	Err   error
}

// used for retrieving entries from updates table
func fetchKeyWorker(resultChan chan readKeyResult, start, end int, ctx context.Context, db *sql.DB) {
	key := make([]byte, 0, end-start)
	result := make([]common.SHA256Output, 0, end-start)

	resultRows, err := db.Query("SELECT * FROM updates LIMIT " + strconv.Itoa(start) + "," + strconv.Itoa(end-start))
	if err != nil {
		resultChan <- readKeyResult{Err: fmt.Errorf("fetchKeyWorker | Query | %w", err)}
		return
	}
	defer resultRows.Close()

	for resultRows.Next() {
		err = resultRows.Scan(&key)
		// sql.NoRowErr should not be omitted.
		if err != nil {
			resultChan <- readKeyResult{Err: fmt.Errorf("fetchKeyWorker | Scan | %w", err)}
			return
		}
		var key32bytes common.SHA256Output
		copy(key32bytes[:], key)
		result = append(result, key32bytes)
	}

	resultChan <- readKeyResult{Keys: result}
}
