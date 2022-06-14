package db

import (
	"database/sql"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
)

// NOTE
// The project contains three tables:
// * Domain entries tables: the table to store domain materials.
// -- Key: domain name hash: 32 bytes VarBinary
// -- Value: Serialized data of domain materials. Use Json to serialize the data structure. Stored as BLOB
// * Tree table: contains the Sparse Merkle Tree. Store the nodes of Sparse Merkle Tree
// * updates table: contains the domain hashes of the changed domains during this update.
//   updates table will be truncated after the Sparse Merkle Tree is updated.

// TableName: enum type of tables
type tableName int

const (
	DomainEntries tableName = iota
	Tree
	Updates
)

type mysqlDB struct {
	db                 *sql.DB
	prepValueProofPath *sql.Stmt // returns the value and the complete proof path
	prepGetValue       *sql.Stmt // returns the value for a node

	prepGetValueDomainEntries    *sql.Stmt // returns the domain entries
	prepUpdateValueDomainEntries *sql.Stmt // update the DomainEntries table

	prepUpdateValueTree    *sql.Stmt // update tree table
	prepGetValueTree       *sql.Stmt // get key-value pair from tree table
	prepDeleteKeyValueTree *sql.Stmt // delete key-value pair from tree table

	prepInsertKeysUpdates *sql.Stmt // update updates table
}

// NewMysqlDB is called to create a new instance of the mysqlDB, initializing certain values,
// like stored procedures.
func NewMysqlDB(db *sql.DB) (*mysqlDB, error) {
	prepValueProofPath, err := db.Prepare("CALL val_and_proof_path(?)")
	if err != nil {
		return nil, fmt.Errorf("NewMysqlDB | preparing statement prepValueProofPath: %w", err)
	}

	prepGetValue, err := db.Prepare("SELECT value from nodes WHERE idhash=?")
	if err != nil {
		return nil, fmt.Errorf("NewMysqlDB | preparing statement prepGetValue: %w", err)
	}

	prepGetValueDomainEntries, err := db.Prepare("SELECT `value` from `domainEntries` WHERE `key`=?")
	if err != nil {
		return nil, fmt.Errorf("NewMysqlDB | preparing statement prepGetValueDomainEntries: %w", err)
	}

	prepUpdateValueDomainEntries, err := db.Prepare("REPLACE into domainEntries (`key`, `value`) values " + repeatStmt(batchSize, 2))
	if err != nil {
		return nil, fmt.Errorf("NewMysqlDB | preparing statement prepUpdateValueDomainEntries: %w", err)
	}

	prepUpdateValueTree, err := db.Prepare("REPLACE into tree (`key`, `value`) values " + repeatStmt(batchSize, 2))
	if err != nil {
		return nil, fmt.Errorf("NewMysqlDB | preparing statement prepUpdateValueTree: %w", err)
	}

	prepGetValueTree, err := db.Prepare("SELECT `value` from `tree` WHERE `key`=?")
	if err != nil {
		return nil, fmt.Errorf("NewMysqlDB | preparing statement prepGetValueTree: %w", err)
	}

	prepDeleteKeyValueTree, err := db.Prepare(repeatStmtForDelete("tree", batchSize))
	if err != nil {
		return nil, fmt.Errorf("NewMysqlDB | preparing statement prepDeleteKeyValueTree: %w", err)
	}

	prepInsertKeysUpdates, err := db.Prepare("INSERT IGNORE into `updates` (`key`) VALUES " + repeatStmt(batchSize, 1))
	if err != nil {
		return nil, fmt.Errorf("NewMysqlDB | preparing statement prepInsertKeysUpdates: %w", err)
	}

	return &mysqlDB{
		db:                           db,
		prepValueProofPath:           prepValueProofPath,
		prepGetValue:                 prepGetValue,
		prepGetValueDomainEntries:    prepGetValueDomainEntries,
		prepUpdateValueDomainEntries: prepUpdateValueDomainEntries,
		prepUpdateValueTree:          prepUpdateValueTree,
		prepGetValueTree:             prepGetValueTree,
		prepDeleteKeyValueTree:       prepDeleteKeyValueTree,
		prepInsertKeysUpdates:        prepInsertKeysUpdates,
	}, nil
}

// Close: close connection
func (c *mysqlDB) Close() error {
	return c.db.Close()
}
