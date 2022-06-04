package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/go-sql-driver/mysql"
)

// NOTE
// The project contains three tables:
// * Domain entries tables: the table to store domain materials.
// -- Key: hex-encoded of domain name hash: hex.EncodeToString(SHA256(domain name))
// -- Value: Serialised data of domain materials. Use Json to serialise the data structure.
// * Tree table: contains the Sparse Merkle Tree. Store the nodes of Sparse Merkle Tree
// * updates table: contains the domain hashes of the changed domains during this update.
//   updates table will be truncated after the Sparse Merkle Tree is updated.

// TableName: enum type of tables
// Currently two tables:
// - DomainEntries table: used to store domain materials(certificates, PC, RPC, etc.)
// - Tree table: store the SMT tree structure
type tableName int

const (
	DomainEntries tableName = iota
	Tree          tableName = iota
	Updates       tableName = iota
)

type mysqlDB struct {
	db                              *sql.DB
	prepNodePath                    *sql.Stmt // returns the node path
	prepValueProofPath              *sql.Stmt // returns the value and the complete proof path
	prepGetValue                    *sql.Stmt // returns the value for a node
	prepGetValueDomainEntries       *sql.Stmt // returns the domain entries
	prepUpdateValueDomainEntries    *sql.Stmt // update the DomainEntries table
	prepDeleteKeyValueDomainEntries *sql.Stmt // delete key value pair from DomainEntries table

	prepUpdateValueTree    *sql.Stmt // update tree table
	prepGetValueTree       *sql.Stmt // get key-value pair from tree table
	prepDeleteKeyValueTree *sql.Stmt // delete key-value pair from tree table

	prepInsertKeysUpdates *sql.Stmt // update updates table
}

func repeatStmt(N int, noOfComponents int) string {
	components := make([]string, noOfComponents)
	for i := 0; i < len(components); i++ {
		components[i] = "?"
	}
	toRepeat := "(" + strings.Join(components, ",") + ")"
	return strings.Repeat(toRepeat+",", N-1) + toRepeat
}

func repeatStmtForDelete(tableName string, N int) string {
	var deleteSB strings.Builder
	queryStr := "DELETE from `" + tableName + "` WHERE `key` IN ("
	deleteSB.WriteString(queryStr)

	isFirst := true
	for i := 0; i < N; i++ {
		if isFirst {
			deleteSB.WriteString("?")
			isFirst = false
		} else {
			deleteSB.WriteString(", ?")
		}
	}

	deleteSB.WriteString(");")
	return deleteSB.String()
}

// NewMysqlDB is called to create a new instance of the mysqlDB, initializing certain values,
// like stored procedures.
func NewMysqlDB(db *sql.DB) (*mysqlDB, error) {
	prepNodePath, err := db.Prepare("SELECT node_path(?)")
	if err != nil {
		return nil, fmt.Errorf("preparing statement prepNodePath: %w", err)
	}

	prepValueProofPath, err := db.Prepare("CALL val_and_proof_path(?)")
	if err != nil {
		return nil, fmt.Errorf("preparing statement prepValueProofPath: %w", err)
	}

	prepGetValue, err := db.Prepare("SELECT value from nodes WHERE idhash=?")
	if err != nil {
		return nil, fmt.Errorf("preparing statement prepGetValue: %w", err)
	}

	prepGetValueDomainEntries, err := db.Prepare("SELECT `value` from `domainEntries` WHERE `key`=?")
	if err != nil {
		return nil, fmt.Errorf("preparing statement prepGetValueDomainEntries: %w", err)
	}

	prepUpdateValueDomainEntries, err := db.Prepare("REPLACE into domainEntries (`key`, `value`) values " + repeatStmt(batchSize, 2))
	if err != nil {
		return nil, fmt.Errorf("preparing statement prepUpdateValueDomainEntries: %w", err)
	}

	prepDeleteKeyValueDomainEntries, err := db.Prepare(repeatStmtForDelete("domainEntries", batchSize))
	if err != nil {
		return nil, fmt.Errorf("preparing statement prepDeleteKeyValueDomainEntries: %w", err)
	}

	prepUpdateValueTree, err := db.Prepare("REPLACE into tree (`key`, `value`) values " + repeatStmt(batchSize, 2))
	if err != nil {
		return nil, fmt.Errorf("preparing statement prepUpdateValueTree: %w", err)
	}

	prepGetValueTree, err := db.Prepare("SELECT `value` from `tree` WHERE `key`=?")
	if err != nil {
		return nil, fmt.Errorf("preparing statement prepGetValueTree: %w", err)
	}

	prepDeleteKeyValueTree, err := db.Prepare(repeatStmtForDelete("tree", batchSize))
	if err != nil {
		return nil, fmt.Errorf("preparing statement prepDeleteKeyValueTree: %w", err)
	}

	prepInsertKeysUpdates, err := db.Prepare("INSERT IGNORE into `updates` (`key`) VALUES " + repeatStmt(batchSize, 1))
	if err != nil {
		return nil, fmt.Errorf("preparing statement prepInsertKeysUpdates: %w", err)
	}

	return &mysqlDB{
		db:                              db,
		prepNodePath:                    prepNodePath,
		prepValueProofPath:              prepValueProofPath,
		prepGetValue:                    prepGetValue,
		prepGetValueDomainEntries:       prepGetValueDomainEntries,
		prepUpdateValueDomainEntries:    prepUpdateValueDomainEntries,
		prepDeleteKeyValueDomainEntries: prepDeleteKeyValueDomainEntries,
		prepUpdateValueTree:             prepUpdateValueTree,
		prepGetValueTree:                prepGetValueTree,
		prepDeleteKeyValueTree:          prepDeleteKeyValueTree,
		prepInsertKeysUpdates:           prepInsertKeysUpdates,
	}, nil
}

// Close: close connection
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
