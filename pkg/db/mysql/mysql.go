package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/netsec-ethz/fpki/pkg/common"
)

const batchSize = 1000

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
	// prepGetUpdatedDomains     *sql.Stmt // get updated domains

	getDomainEntriesUpdateStmts prepStmtGetter // used to update key-values in domain entries
	getTreeStructureUpdateStmts prepStmtGetter // used to update key-values in the tree table
	getUpdatesInsertStmts       prepStmtGetter // used to insert entries in the updates table
	getTreeDeleteStmts          prepStmtGetter // used to delete entries in the tree table

	getProofLimiter chan struct{}
}

// NewMysqlDB is called to create a new instance of the mysqlDB, initializing certain values,
// like stored procedures.
func NewMysqlDB(db *sql.DB) (*mysqlDB, error) {
	// prepGetValueDomainEntries, err := db.Prepare("SELECT `value` from `domainEntries` WHERE `key`=?")
	// if err != nil {
	// 	return nil, fmt.Errorf("NewMysqlDB | preparing statement prepGetValueDomainEntries: %w", err)
	// }
	// prepGetValueTree, err := db.Prepare("SELECT `value` from `tree` WHERE `key32`=?")
	// if err != nil {
	// 	return nil, fmt.Errorf("NewMysqlDB | preparing statement prepGetValueTree: %w", err)
	// }
	// prepGetUpdatedDomains, err := db.Prepare("SELECT `key` FROM `updates`")
	// if err != nil {
	// 	return nil, fmt.Errorf("NewMysqlDB | preparing statement prepGetUpdatedDomains: %w", err)
	// }

	// str := "REPLACE into domainEntries (`key`, `value`) values " + repeatStmt(batchSize, 2)
	// prepReplaceDomainEntries, err := db.Prepare(str)
	// if err != nil {
	// 	return nil, fmt.Errorf("NewMysqlDB | preparing statement prepReplaceDomainEntries: %w", err)
	// }
	// str = "REPLACE into tree (`key32`, `value`) values " + repeatStmt(batchSize, 2)
	// prepReplaceTree, err := db.Prepare(str)
	// if err != nil {
	// 	return nil, fmt.Errorf("NewMysqlDB | preparing statement prepReplaceTree: %w", err)
	// }
	// str = "REPLACE into `updates` (`key`) VALUES " + repeatStmt(batchSize, 1)
	// prepReplaceUpdates, err := db.Prepare(str)
	// if err != nil {
	// 	return nil, fmt.Errorf("NewMysqlDB | preparing statement prepReplaceUpdates: %w", err)
	// }
	// str = "DELETE from `tree` WHERE `key32` IN " + repeatStmt(1, batchSize)
	// prepDeleteUpdates, err := db.Prepare(str)
	// if err != nil {
	// 	return nil, fmt.Errorf("NewMysqlDB | preparing statement prepDeleteUpdates: %w", err)
	// }

	return &mysqlDB{
		db: db,
		// prepGetValueDomainEntries: prepGetValueDomainEntries,
		// prepGetValueTree:          prepGetValueTree,
		// prepGetUpdatedDomains:     prepGetUpdatedDomains,
		// getDomainEntriesUpdateStmts: func(count int) (*sql.Stmt, *sql.Stmt) {
		// 	str = "REPLACE into domainEntries (`key`, `value`) values " + repeatStmt(count, 2)
		// 	prepPartial, err := db.Prepare(str)
		// 	if err != nil {
		// 		panic(err)
		// 	}
		// 	return prepReplaceDomainEntries, prepPartial
		// },
		// getTreeStructureUpdateStmts: func(count int) (*sql.Stmt, *sql.Stmt) {
		// 	str := "REPLACE into tree (`key`, `value`) values " + repeatStmt(count, 2)
		// 	prepPartial, err := db.Prepare(str)
		// 	if err != nil {
		// 		panic(err)
		// 	}
		// 	return prepReplaceTree, prepPartial
		// },
		// getUpdatesInsertStmts: func(count int) (*sql.Stmt, *sql.Stmt) {
		// 	str := "REPLACE into `updates` (`key`) VALUES " + repeatStmt(count, 1)
		// 	prepPartial, err := db.Prepare(str)
		// 	if err != nil {
		// 		panic(err)
		// 	}
		// 	return prepReplaceUpdates, prepPartial
		// },
		// getTreeDeleteStmts: func(count int) (*sql.Stmt, *sql.Stmt) {
		// 	if count == 0 {
		// 		return prepDeleteUpdates, nil
		// 	}
		// 	str := "DELETE from `tree` WHERE `key` IN " + repeatStmt(1, count)
		// 	prepPartial, err := db.Prepare(str)
		// 	if err != nil {
		// 		panic(err)
		// 	}
		// 	return prepDeleteUpdates, prepPartial
		// },
		getProofLimiter: make(chan struct{}, 128),
	}, nil
}

func (c *mysqlDB) DB() *sql.DB {
	return c.db
}

// Close: close connection
func (c *mysqlDB) Close() error {
	// c.prepGetValueTree.Close()
	// c.prepGetValueDomainEntries.Close()
	return c.db.Close()
}

func (c *mysqlDB) TruncateAllTables(ctx context.Context) error {
	tables := []string{
		"tree",
		"root",
		"certs",
		"domains",
		"domain_payloads",
		"dirty",
	}
	for _, t := range tables {
		if _, err := c.db.ExecContext(ctx, fmt.Sprintf("TRUNCATE %s", t)); err != nil {
			return err
		}
	}
	return nil
}

func (c *mysqlDB) LoadRoot(ctx context.Context) (*common.SHA256Output, error) {
	var key []byte
	if err := c.db.QueryRowContext(ctx, "SELECT key32 FROM root").Scan(&key); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("error obtaining the root entry: %w", err)
	}
	return (*common.SHA256Output)(key), nil
}

// CheckCertsExist returns a slice of true/false values. Each value indicates if
// the corresponding certificate identified by its ID is already present in the DB.
func (c *mysqlDB) CheckCertsExist(ctx context.Context, ids []*common.SHA256Output) ([]bool, error) {
	if len(ids) == 0 {
		// If empty, return empty.
		return nil, nil
	}
	// Slice to be used in the SQL query:
	data := make([]interface{}, len(ids))
	for i, id := range ids {
		data[i] = id[:]
	}

	// Prepare a query that returns a vector of bits, 1 means ID is present, 0 means is not.
	elems := make([]string, len(data))
	for i := range elems {
		elems[i] = "SELECT ? AS id"
	}

	// The query means: join two tables, one with the values I am passing as arguments (those
	// are the ids) and the certs table, and for those that exist write a 1, otherwise a 0.
	// Finally, group_concat all rows into just one field of type string.
	str := "SELECT GROUP_CONCAT(presence SEPARATOR '') FROM (" +
		"SELECT (CASE WHEN certs.id IS NOT NULL THEN 1 ELSE 0 END) AS presence FROM (" +
		strings.Join(elems, " UNION ALL ") +
		") AS request left JOIN ( SELECT id FROM certs ) AS certs ON certs.id = request.id" +
		") AS t"

	// Return slice of booleans:
	present := make([]bool, len(ids))

	var value string
	if err := c.db.QueryRowContext(ctx, str, data...).Scan(&value); err != nil {
		return nil, err
	}
	for i, c := range value {
		if c == '1' {
			present[i] = true
		}
	}

	return present, nil
}

func (c *mysqlDB) InsertCerts(ctx context.Context, ids, parents []*common.SHA256Output,
	expirations []*time.Time, payloads [][]byte) error {

	if len(ids) == 0 {
		return nil
	}
	// TODO(juagargi) set a prepared statement in constructor
	// Because the primary key is the SHA256 of the payload, if there is a clash, it must
	// be that the certificates are identical. Thus always REPLACE or INSERT IGNORE.
	const N = 4
	str := "REPLACE INTO certs (id, parent, expiration, payload) VALUES " + repeatStmt(len(ids), N)
	data := make([]interface{}, N*len(ids))
	for i := range ids {
		data[i*N] = ids[i][:]
		if parents[i] != nil {
			data[i*N+1] = parents[i][:]
		}
		data[i*N+2] = expirations[i]
		data[i*N+3] = payloads[i]
	}
	_, err := c.db.Exec(str, data...)
	if err != nil {
		return err
	}

	return nil
}

// UpdateDomainsWithCerts updates both the domains and the dirty tables.
func (c *mysqlDB) UpdateDomainsWithCerts(ctx context.Context, certIDs, domainIDs []*common.SHA256Output,
	domainNames []string) error {

	if len(certIDs) == 0 {
		return nil
	}
	// First insert into domains:
	const N = 3
	str := "INSERT IGNORE INTO domains (cert_id,domain_id,domain_name) VALUES " +
		repeatStmt(len(certIDs), N)
	data := make([]interface{}, N*len(certIDs))
	for i := range certIDs {
		data[i*N] = certIDs[i][:]
		data[i*N+1] = domainIDs[i][:]
		data[i*N+2] = domainNames[i]
	}
	_, err := c.db.Exec(str, data...)
	if err != nil {
		return err
	}

	// Now insert into dirty.
	str = "REPLACE INTO dirty (domain_id) VALUES " + repeatStmt(len(domainIDs), 1)
	data = make([]interface{}, len(domainIDs))
	for i, id := range domainIDs {
		data[i] = id[:]
	}
	_, err = c.db.Exec(str, data...)

	return err
}

// repeatStmt returns  ( (?,..dimensions..,?), ...elemCount...  )
// Use it like repeatStmt(1, len(IDs)) to obtain (?,?,...)
func repeatStmt(elemCount int, dimensions int) string {
	components := make([]string, dimensions)
	for i := 0; i < len(components); i++ {
		components[i] = "?"
	}
	toRepeat := "(" + strings.Join(components, ",") + ")"
	return strings.Repeat(toRepeat+",", elemCount-1) + toRepeat
}
