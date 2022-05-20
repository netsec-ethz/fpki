package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type mysqlDB struct {
	db                           *sql.DB
	prepNodePath                 *sql.Stmt // returns the node path
	prepValueProofPath           *sql.Stmt // returns the value and the complete proof path
	prepGetValue                 *sql.Stmt // returns the value for a node
	prepGetValueDomainEntries    *sql.Stmt // returns the domain entries
	prepUpdateValueDomainEntries *sql.Stmt // update the DomainEntries table
}

// NewMysqlDB is called to create a new instance of the mysqlDB, initializing certain values,
// like stored procedures.
func NewMysqlDB(db *sql.DB) (*mysqlDB, error) {
	prepNodePath, err := db.Prepare("SELECT node_path(?)")
	if err != nil {
		return nil, fmt.Errorf("preparing statement: %w", err)
	}
	prepValueProofPath, err := db.Prepare("CALL val_and_proof_path(?)")
	if err != nil {
		return nil, fmt.Errorf("preparing statement: %w", err)
	}
	prepGetValue, err := db.Prepare("SELECT value from nodes WHERE idhash=?")
	if err != nil {
		return nil, fmt.Errorf("preparing statement: %w", err)
	}
	prepGetValueDomainEntries, err := db.Prepare("SELECT `key`, `value` from `domainEntries` WHERE `key`=?")
	if err != nil {
		return nil, fmt.Errorf("preparing statement prepGetValueDomainEntries: %w", err)
	}

	prepUpdateValueDomainEntries, err := db.Prepare("REPLACE into domainEntries (`key`, `value`) values " + repeatStmt(1000, 2))
	if err != nil {
		return nil, fmt.Errorf("preparing statement prepUpdateValueDomainEntries: %w", err)
	}
	return &mysqlDB{
		db:                           db,
		prepNodePath:                 prepNodePath,
		prepValueProofPath:           prepValueProofPath,
		prepGetValue:                 prepGetValue,
		prepGetValueDomainEntries:    prepGetValueDomainEntries,
		prepUpdateValueDomainEntries: prepUpdateValueDomainEntries,
	}, nil
}

func (c *mysqlDB) Close() error {
	return c.db.Close()
}

// RetrieveValue returns the value associated with the node.
func (c *mysqlDB) RetrieveValue(ctx context.Context, id FullID) ([]byte, error) {
	var val []byte
	row := c.prepGetValue.QueryRowContext(ctx, id[:])
	if err := row.Scan(&val); err != nil {
		return nil, err
	}
	return val, nil
}

// RetrieveNode returns the value and the proof path (without the root) for a given node.
// Since each one of the steps of the proof path has a fixed size, returning the path
// as a slice is sufficient to know how many steps there were in the proof path.
func (c *mysqlDB) RetrieveNode(ctx context.Context, id FullID) ([]byte, []byte, error) {
	var val, proofPath []byte
	row := c.prepValueProofPath.QueryRowContext(ctx, id[:])
	if err := row.Scan(&val, &proofPath); err != nil {
		return nil, nil, err
	}
	return val, proofPath, nil
}

func (c *mysqlDB) RetrieveKeyValuePairMultiThread(ctx context.Context, id []string, numOfRoutine int) (*KeyValueResult, error) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	count := len(id)
	step := count / numOfRoutine

	// to simplify code, check that we run all queries: count must be divisible by routine count
	if count%numOfRoutine != 0 {
		return nil, fmt.Errorf("RetrieveKeyValuePairMultiThread | count / numOfRoutine != 0")
	}

	resultChan := make(chan KeyValueResult)
	for r := 0; r < numOfRoutine; r++ {
		go fetchKeyValuePairWorker(resultChan, id[r*step:r*step+step-1], *c.prepGetValueDomainEntries, ctx)
	}

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

	return &KeyValueResult{Pairs: keyValuePairs}, nil
}

func fetchKeyValuePairWorker(resultChan chan KeyValueResult, keys []string, stmt sql.Stmt, ctx context.Context) {
	numOfWork := len(keys)
	pairs := []KeyValuePair{}
	var value []byte

work_loop:
	for i := 0; i < numOfWork; i++ {
		err := stmt.QueryRowContext(ctx, keys[i]).Scan(&value)
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

func (c *mysqlDB) UpdateKeyValuePairBatches(ctx context.Context, keyValuePairs []KeyValuePair) error {
	dataLen := len(keyValuePairs)
	for i := 0; i*1000 < dataLen; i++ {
		data := make([]interface{}, 2*1000) // 2 elements per record ()

		for j := 0; j < 1000; j++ {
			data[2*j] = keyValuePairs[i*1000+j].Key
			data[2*j+1] = keyValuePairs[i*1000+j].Value
		}

		_, err := c.prepUpdateValueDomainEntries.Exec(data...)
		if err != nil {
			return fmt.Errorf("UpdateKeyValuePairBatches | Exec | %w", err)
		}
	}
	return nil
}
