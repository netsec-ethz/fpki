package db

import (
	"database/sql"
	"fmt"
	"strings"

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

type prepStmtGetter func(count int) (*sql.Stmt, *sql.Stmt)

type mysqlDB struct {
	db *sql.DB

	prepGetValueDomainEntries *sql.Stmt // returns the domain entries
	prepGetValueTree          *sql.Stmt // get key-value pair from tree table
	prepGetUpdatedDomains     *sql.Stmt // get updated domains

	getDomainEntriesUpdateStmts prepStmtGetter // used to update key-values in domain entries
	getTreeStructureUpdateStmts prepStmtGetter // used to update key-values in the tree table
	getUpdatesInsertStmts       prepStmtGetter // used to insert entries in the updates table
	getTreeDeleteStmts          prepStmtGetter // used to delete entries in the tree table

	getProofLimiter chan struct{}
}

// NewMysqlDB is called to create a new instance of the mysqlDB, initializing certain values,
// like stored procedures.
func NewMysqlDB(db *sql.DB) (*mysqlDB, error) {
	prepGetValueDomainEntries, err := db.Prepare("SELECT `value` from `domainEntries` WHERE `key`=?")
	if err != nil {
		return nil, fmt.Errorf("NewMysqlDB | preparing statement prepGetValueDomainEntries: %w", err)
	}
	prepGetValueTree, err := db.Prepare("SELECT `value` from `tree` WHERE `key`=?")
	if err != nil {
		return nil, fmt.Errorf("NewMysqlDB | preparing statement prepGetValueTree: %w", err)
	}
	prepGetUpdatedDomains, err := db.Prepare("SELECT `key` FROM `updates`")
	if err != nil {
		return nil, fmt.Errorf("NewMysqlDB | preparing statement prepGetUpdatedDomains: %w", err)
	}

	str := "REPLACE into domainEntries (`key`, `value`) values " + repeatStmt(batchSize, 2)
	prepReplaceDomainEntries, err := db.Prepare(str)
	if err != nil {
		return nil, fmt.Errorf("NewMysqlDB | preparing statement prepReplaceDomainEntries: %w", err)
	}
	str = "REPLACE into tree (`key`, `value`) values " + repeatStmt(batchSize, 2)
	prepReplaceTree, err := db.Prepare(str)
	if err != nil {
		return nil, fmt.Errorf("NewMysqlDB | preparing statement prepReplaceTree: %w", err)
	}
	str = "REPLACE into `updates` (`key`) VALUES " + repeatStmt(batchSize, 1)
	prepReplaceUpdates, err := db.Prepare(str)
	if err != nil {
		return nil, fmt.Errorf("NewMysqlDB | preparing statement prepReplaceUpdates: %w", err)
	}
	str = "DELETE from `tree` WHERE `key` IN " + repeatStmt(1, batchSize)
	prepDeleteUpdates, err := db.Prepare(str)
	if err != nil {
		return nil, fmt.Errorf("NewMysqlDB | preparing statement prepDeleteUpdates: %w", err)
	}

	return &mysqlDB{
		db:                        db,
		prepGetValueDomainEntries: prepGetValueDomainEntries,
		prepGetValueTree:          prepGetValueTree,
		prepGetUpdatedDomains:     prepGetUpdatedDomains,
		getDomainEntriesUpdateStmts: func(count int) (*sql.Stmt, *sql.Stmt) {
			str = "REPLACE into domainEntries (`key`, `value`) values " + repeatStmt(count, 2)
			prepPartial, err := db.Prepare(str)
			if err != nil {
				panic(err)
			}
			return prepReplaceDomainEntries, prepPartial
		},
		getTreeStructureUpdateStmts: func(count int) (*sql.Stmt, *sql.Stmt) {
			str := "REPLACE into tree (`key`, `value`) values " + repeatStmt(count, 2)
			prepPartial, err := db.Prepare(str)
			if err != nil {
				panic(err)
			}
			return prepReplaceTree, prepPartial
		},
		getUpdatesInsertStmts: func(count int) (*sql.Stmt, *sql.Stmt) {
			str := "REPLACE into `updates` (`key`) VALUES " + repeatStmt(count, 1)
			prepPartial, err := db.Prepare(str)
			if err != nil {
				panic(err)
			}
			return prepReplaceUpdates, prepPartial
		},
		getTreeDeleteStmts: func(count int) (*sql.Stmt, *sql.Stmt) {
			if count == 0 {
				return prepDeleteUpdates, nil
			}
			str := "DELETE from `tree` WHERE `key` IN " + repeatStmt(1, count)
			prepPartial, err := db.Prepare(str)
			if err != nil {
				panic(err)
			}
			return prepDeleteUpdates, prepPartial
		},
		getProofLimiter: make(chan struct{}, 128),
	}, nil
}

func (c *mysqlDB) DB() *sql.DB {
	return c.db
}

// Close: close connection
func (c *mysqlDB) Close() error {
	c.prepGetValueTree.Close()
	c.prepGetValueDomainEntries.Close()
	return c.db.Close()
}

func (c *mysqlDB) TruncateAllTables() error {
	tables := []string{
		"domainEntries",
		"tree",
		"updates",
	}
	for _, t := range tables {
		if _, err := c.db.Exec(fmt.Sprintf("DELETE FROM %s", t)); err != nil {
			return err
		}
	}
	return nil
}

func (c *mysqlDB) DisableIndexing(table string) error {
	_, err := c.db.Exec(fmt.Sprintf("ALTER TABLE `%s` DISABLE KEYS", table))
	return err
}

func (c *mysqlDB) EnableIndexing(table string) error {
	_, err := c.db.Exec(fmt.Sprintf("ALTER TABLE `%s` ENABLE KEYS", table))
	return err
}

// repeatStmt returns  ( (?,..inner..,?), ...outer...  )
func repeatStmt(outer int, inner int) string {
	components := make([]string, inner)
	for i := 0; i < len(components); i++ {
		components[i] = "?"
	}
	toRepeat := "(" + strings.Join(components, ",") + ")"
	return strings.Repeat(toRepeat+",", outer-1) + toRepeat
}
