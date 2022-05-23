package db

import (
	"context"
	"database/sql"
	"fmt"
	"math/rand"
	"strconv"
	"time"
)

type ReadKeyResult struct {
	Keys []string
	Err  error
}

func (c *mysqlDB) RetrieveOneKeyValuePair(ctx context.Context, id string, tableName TableName) (*KeyValuePair, error) {
	var value []byte
	var stmt *sql.Stmt

	switch {
	case tableName == DomainEntries:
		stmt = c.prepGetValueDomainEntries
	case tableName == Tree:
		stmt = c.prepGetValueTree
	default:
		return nil, fmt.Errorf("RetrieveOneKeyValuePair : Table name not supported")
	}

	start := time.Now()
	result := stmt.QueryRow(id)
	end := time.Now()
	fmt.Println("db read: ", end.Sub(start))
	err := result.Scan(&value)
	if err != nil {
		switch {
		case err != sql.ErrNoRows:
			return nil, err
		case err == sql.ErrNoRows:
			return &KeyValuePair{}, nil
		}
	}

	return &KeyValuePair{Key: id, Value: value}, nil
}

func (c *mysqlDB) RetrieveKeyValuePairMultiThread(ctx context.Context, id []string, numOfRoutine int, tableName TableName) ([]KeyValuePair, error) {
	var stmt *sql.Stmt
	switch {
	case tableName == DomainEntries:
		stmt = c.prepGetValueDomainEntries
	case tableName == Tree:
		stmt = c.prepGetValueTree
	default:
		return nil, fmt.Errorf("RetrieveKeyValuePairMultiThread : Table name not supported")
	}

	if len(id) < numOfRoutine {
		numOfRoutine = len(id)
	}

	count := len(id)
	step := count / numOfRoutine

	resultChan := make(chan KeyValueResult)
	for r := 0; r < numOfRoutine-1; r++ {
		go fetchKeyValuePairWorker(resultChan, id[r*step:r*step+step], stmt, ctx)
	}
	// let the final one do the rest of the work
	go fetchKeyValuePairWorker(resultChan, id[(numOfRoutine-1)*step:count], stmt, ctx)

	finishedWorker := 0
	keyValuePairs := []KeyValuePair{}

	for numOfRoutine > finishedWorker {
		newResult := <-resultChan
		if newResult.Err != nil {
			return nil, fmt.Errorf("RetrieveKeyValuePairMultiThread | %w", newResult.Err)
		}
		keyValuePairs = append(keyValuePairs, newResult.Pairs...)
		finishedWorker++
	}

	return keyValuePairs, nil
}

func fetchKeyValuePairWorker(resultChan chan KeyValueResult, keys []string, stmt *sql.Stmt, ctx context.Context) {
	numOfWork := len(keys)
	pairs := []KeyValuePair{}
	var value []byte

work_loop:
	for i := 0; i < numOfWork; i++ {
		result := stmt.QueryRow(keys[i])
		err := result.Scan(&value)
		if err != nil {
			switch {
			case err != sql.ErrNoRows:
				resultChan <- KeyValueResult{Err: err}
				return
			case err == sql.ErrNoRows:
				continue work_loop
			}
		}
		pairs = append(pairs, KeyValuePair{Key: keys[i], Value: value})
	}

	resultChan <- KeyValueResult{Pairs: pairs}
}

func getRandomInt() int {
	return rand.Intn(50)
}

func (c *mysqlDB) RetrieveUpdatedDomainMultiThread(ctx context.Context, perQueryLimit int) ([]string, error) {
	count, err := c.RetrieveTableRowsCount(ctx)
	if err != nil {
		return nil, fmt.Errorf("RetrieveUpdatedDomainMultiThread | RetrieveTableRowsCount | %w", err)
	}

	numberOfWorker := 1
	if count > perQueryLimit {
		numberOfWorker = count/perQueryLimit + 1
	}

	var step int
	if numberOfWorker == 1 {
		step = count
	} else {
		step = count / numberOfWorker
	}

	resultChan := make(chan ReadKeyResult)
	for r := 0; r < numberOfWorker-1; r++ {
		go fetchKeyWorker(resultChan, r*step, r*step+step, ctx, c.db)
	}
	// let the final one do the rest of the work
	go fetchKeyWorker(resultChan, (numberOfWorker-1)*step, count+1, ctx, c.db)

	finishedWorker := 0
	keys := []string{}

	for numberOfWorker > finishedWorker {
		newResult := <-resultChan
		if newResult.Err != nil {
			switch {
			case newResult.Err == sql.ErrNoRows:
				continue
			case newResult.Err != sql.ErrNoRows:
				return nil, fmt.Errorf("RetrieveKeyValuePairMultiThread | %w", newResult.Err)
			}
		}
		keys = append(keys, newResult.Keys...)
		finishedWorker++
	}

	if count != len(keys) {
		return nil, fmt.Errorf("RetrieveUpdatedDomainMultiThread | incomplete fetching")
	}

	err = c.TruncateUpdatesTable(ctx)
	if err != nil {
		return nil, fmt.Errorf("RetrieveUpdatedDomainMultiThread | TruncateUpdatesTable | %w", err)
	}

	return keys, nil
}

func fetchKeyWorker(resultChan chan ReadKeyResult, start, end int, ctx context.Context, db *sql.DB) {
	var key string
	result := []string{}

	stmt, err := db.Prepare("SELECT * FROM updates LIMIT " + strconv.Itoa(start) + "," + strconv.Itoa(end-start))
	if err != nil {
		resultChan <- ReadKeyResult{Err: fmt.Errorf("fetchKeyWorker | SELECT * | %w", err)}
	}
	resultRows, err := stmt.Query()
	if err != nil {
		resultChan <- ReadKeyResult{Err: fmt.Errorf("fetchKeyWorker | Query | %w", err)}
	}
	defer resultRows.Close()
	for resultRows.Next() {
		err = resultRows.Scan(&key)
		if err != nil {
			resultChan <- ReadKeyResult{Err: fmt.Errorf("fetchKeyWorker | Scan | %w", err)}
		}
		result = append(result, key)
	}

	resultChan <- ReadKeyResult{Keys: result}
}

func (c *mysqlDB) RetrieveTableRowsCount(ctx context.Context) (int, error) {
	stmt, err := c.db.Prepare("SELECT COUNT(*) FROM updates")
	if err != nil {
		return 0, fmt.Errorf("RetrieveTableRowsCount | Prepare | %w", err)
	}

	var number int
	err = stmt.QueryRow().Scan(&number)
	if err != nil {
		return 0, fmt.Errorf("RetrieveTableRowsCount | Scan | %w", err)
	}
	return number, nil
}
