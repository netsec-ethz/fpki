package db

import (
	"context"
	"database/sql"
	"fmt"
)

type mysqlDB struct {
	db                 *sql.DB
	prepNodePath       *sql.Stmt // returns the node path
	prepValueProofPath *sql.Stmt // returns the value and the complete proof path
	prepGetValue       *sql.Stmt // returns the value for a node
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
	return &mysqlDB{
		db:                 db,
		prepNodePath:       prepNodePath,
		prepValueProofPath: prepValueProofPath,
		prepGetValue:       prepGetValue,
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
