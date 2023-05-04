package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
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
		"domains",
		"certs",
		"domain_certs",
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
		elems[i] = "SELECT ? AS cert_id"
	}

	// The query means: join two tables, one with the values I am passing as arguments (those
	// are the ids) and the certs table, and for those that exist write a 1, otherwise a 0.
	// Finally, group_concat all rows into just one field of type string.
	str := "SELECT GROUP_CONCAT(presence SEPARATOR '') FROM (" +
		"SELECT (CASE WHEN certs.cert_id IS NOT NULL THEN 1 ELSE 0 END) AS presence FROM (" +
		strings.Join(elems, " UNION ALL ") +
		") AS request LEFT JOIN ( SELECT cert_id FROM certs ) AS certs ON " +
		"certs.cert_id = request.cert_id) AS t"

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

// CheckPoliciesExist returns a slice of true/false values. Each value indicates if
// the corresponding certificate identified by its ID is already present in the DB.
func (c *mysqlDB) CheckPoliciesExist(ctx context.Context, ids []*common.SHA256Output) (
	[]bool, error) {

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
		elems[i] = "SELECT ? AS policy_id"
	}

	// The query means: join two tables, one with the values I am passing as arguments (those
	// are the ids) and the policies table, and for those that exist write a 1, otherwise a 0.
	// Finally, group_concat all rows into just one field of type string.
	str := "SELECT GROUP_CONCAT(presence SEPARATOR '') FROM (" +
		"SELECT (CASE WHEN policies.policy_id IS NOT NULL THEN 1 ELSE 0 END) AS presence FROM (" +
		strings.Join(elems, " UNION ALL ") +
		") AS request LEFT JOIN ( SELECT policy_id FROM policies ) AS policies ON " +
		"policies.policy_id = request.policy_id) AS t"

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
	str := "REPLACE INTO certs (cert_id, parent_id, expiration, payload) VALUES " +
		repeatStmt(len(ids), N)
	data := make([]interface{}, N*len(ids))
	for i := range ids {
		data[i*N] = ids[i][:]
		if parents[i] != nil {
			data[i*N+1] = parents[i][:]
		}
		data[i*N+2] = expirations[i]
		data[i*N+3] = payloads[i]
	}
	_, err := c.db.ExecContext(ctx, str, data...)
	if err != nil {
		return err
	}

	return nil
}

func (c *mysqlDB) InsertPolicies(ctx context.Context, ids, parents []*common.SHA256Output,
	expirations []*time.Time, payloads [][]byte) error {

	if len(ids) == 0 {
		return nil
	}
	// TODO(juagargi) set a prepared statement in constructor
	// Because the primary key is the SHA256 of the payload, if there is a clash, it must
	// be that the certificates are identical. Thus always REPLACE or INSERT IGNORE.
	const N = 4
	str := "REPLACE INTO policies (policy_id, parent_id, expiration, payload) VALUES " +
		repeatStmt(len(ids), N)
	data := make([]interface{}, N*len(ids))
	for i := range ids {
		data[i*N] = ids[i][:]
		if parents[i] != nil {
			data[i*N+1] = parents[i][:]
		}
		data[i*N+2] = expirations[i]
		data[i*N+3] = payloads[i]
	}
	_, err := c.db.ExecContext(ctx, str, data...)
	if err != nil {
		return err
	}

	return nil
}

func (c *mysqlDB) UpdateDomains(ctx context.Context, domainIDs []*common.SHA256Output,
	domainNames []string) error {

	if len(domainIDs) == 0 {
		return nil
	}

	// Make the list of domains unique, attach the name to each unique ID.
	domainIDsSet := make(map[common.SHA256Output]string)
	for i, id := range domainIDs {
		domainIDsSet[*id] = domainNames[i]
	}

	// Insert into dirty.
	str := "REPLACE INTO dirty (domain_id) VALUES " + repeatStmt(len(domainIDsSet), 1)
	data := make([]interface{}, len(domainIDsSet))
	i := 0
	for k := range domainIDsSet {
		k := k // Because k changes during the loop, we need a local copy that doesn't.
		data[i] = k[:]
		i++
	}
	_, err := c.db.ExecContext(ctx, str, data...)
	if err != nil {
		return err
	}

	// Insert into domains.
	str = "INSERT IGNORE INTO domains (domain_id,domain_name) VALUES " +
		repeatStmt(len(domainIDsSet), 2)
	data = make([]interface{}, 2*len(domainIDsSet))
	i = 0
	for k, v := range domainIDsSet {
		k := k
		data[2*i] = k[:]
		data[2*i+1] = v
		i++
	}
	_, err = c.db.ExecContext(ctx, str, data...)

	return err
}

// UpdateDomainCerts updates the domain_certs table.
func (c *mysqlDB) UpdateDomainCerts(ctx context.Context,
	domainIDs, certIDs []*common.SHA256Output) error {

	if len(domainIDs) == 0 {
		return nil
	}
	// Insert into domain_certs:
	str := "INSERT IGNORE INTO domain_certs (domain_id,cert_id) VALUES " +
		repeatStmt(len(certIDs), 2)
	data := make([]interface{}, 2*len(certIDs))
	for i := range certIDs {
		data[2*i] = domainIDs[i][:]
		data[2*i+1] = certIDs[i][:]
	}
	_, err := c.db.ExecContext(ctx, str, data...)

	return err
}

// UpdateDomainPolicies updates the domain_certs table.
func (c *mysqlDB) UpdateDomainPolicies(ctx context.Context,
	domainIDs, policyIDs []*common.SHA256Output) error {

	if len(domainIDs) == 0 {
		return nil
	}
	// Insert into domain_certs:
	str := "INSERT IGNORE INTO domain_policies (domain_id,policy_id) VALUES " +
		repeatStmt(len(policyIDs), 2)
	data := make([]interface{}, 2*len(policyIDs))
	for i := range policyIDs {
		data[2*i] = domainIDs[i][:]
		data[2*i+1] = policyIDs[i][:]
	}
	_, err := c.db.ExecContext(ctx, str, data...)

	return err
}

func (c *mysqlDB) ReplaceDirtyDomainPayloads(ctx context.Context, firstRow, lastRow int) error {
	// Call the certificate coalescing stored procedure with these parameters.
	str := "CALL calc_dirty_domains_certs(?,?)"
	_, err := c.db.ExecContext(ctx, str, firstRow, lastRow)
	if err != nil {
		return fmt.Errorf("coalescing certificates for domains: %w", err)
	}

	// Call the policy coalescing stored procedure with these parameters.
	str = "CALL calc_dirty_domains_policies(?,?)"
	_, err = c.db.ExecContext(ctx, str, firstRow, lastRow)
	if err != nil {
		return fmt.Errorf("coalescing policies for domains: %w", err)
	}
	return nil
}

// RetrieveDomainCertificatesPayload retrieves the domain's certificate payload ID and the payload itself,
// given the domain ID.
func (c *mysqlDB) RetrieveDomainCertificatesPayload(ctx context.Context, domainID common.SHA256Output,
) (*common.SHA256Output, []byte, error) {

	str := "SELECT cert_ids_id, cert_ids FROM domain_payloads WHERE domain_id = ?"
	var certIDsID, certIDs []byte
	err := c.db.QueryRowContext(ctx, str, domainID[:]).Scan(&certIDsID, &certIDs)
	if err != nil && err != sql.ErrNoRows {
		return nil, nil, fmt.Errorf("RetrieveDomainCertificatesPayload | %w", err)
	}
	var IDptr *common.SHA256Output
	if certIDsID != nil {
		IDptr = (*common.SHA256Output)(certIDsID)
	}
	return IDptr, certIDs, nil
}

func (c *mysqlDB) RetrieveDomainPoliciesPayload(ctx context.Context, domainID common.SHA256Output,
) (*common.SHA256Output, []byte, error) {

	str := "SELECT policy_ids_id, policy_ids FROM domain_payloads WHERE domain_id = ?"
	var policyIDsID, policyIDs []byte
	err := c.db.QueryRowContext(ctx, str, domainID[:]).Scan(&policyIDsID, &policyIDs)
	if err != nil && err != sql.ErrNoRows {
		return nil, nil, fmt.Errorf("RetrieveDomainPoliciesPayload | %w", err)
	}
	var IDptr *common.SHA256Output
	if policyIDsID != nil {
		IDptr = (*common.SHA256Output)(policyIDsID)
	}
	return IDptr, policyIDs, nil
}

// RetrieveDomainEntries: Retrieve a list of key-value pairs from domain entries table
// No sql.ErrNoRows will be thrown, if some records does not exist. Check the length of result
func (c *mysqlDB) RetrieveDomainEntries(ctx context.Context, domainIDs []*common.SHA256Output,
) ([]*db.KeyValuePair, error) {

	if len(domainIDs) == 0 {
		return nil, nil
	}

	// Retrieve the certificate and policy IDs for each domain ID.
	str := "SELECT domain_id,cert_ids,policy_ids FROM domain_payloads WHERE domain_id IN " +
		repeatStmt(1, len(domainIDs))
	params := make([]interface{}, len(domainIDs))
	for i, id := range domainIDs {
		params[i] = id[:]
	}
	rows, err := c.db.QueryContext(ctx, str, params...)
	if err != nil {
		return nil, fmt.Errorf("error obtaining payloads for domains: %w", err)
	}
	pairs := make([]*db.KeyValuePair, 0, len(domainIDs))
	for rows.Next() {
		var id, certIDs, policyIDs []byte
		err := rows.Scan(&id, &certIDs, &policyIDs)
		if err != nil {
			return nil, fmt.Errorf("error scanning domain ID and its certs/policies")
		}
		// Unfold the byte streams into IDs, sort them, and fold again.
		allIDs := append(common.BytesToIDs(certIDs), common.BytesToIDs(policyIDs)...)
		pairs = append(pairs, &db.KeyValuePair{
			Key:   *(*common.SHA256Output)(id),
			Value: common.SortIDsAndGlue(allIDs),
		})
	}
	return pairs, nil
}

// used for retrieving key value pair
func (c *mysqlDB) retrieveDomainEntriesOld(ctx context.Context, keys []*common.SHA256Output) (
	[]*db.KeyValuePair, error) {
	str := "SELECT `key`, `value` FROM domainEntries WHERE `key` IN " + repeatStmt(1, len(keys))
	args := make([]interface{}, len(keys))
	for i, k := range keys {
		k := k         // XXX(juagargi): create a copy
		args[i] = k[:] // assign the slice covering the copy (the original k changes !!)
	}
	rows, err := c.db.QueryContext(ctx, str, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var k, v []byte
	domainEntries := make([]*db.KeyValuePair, 0, len(keys))
	for rows.Next() {
		if err = rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		domainEntries = append(domainEntries, &db.KeyValuePair{
			Key:   *(*common.SHA256Output)(k),
			Value: v,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return domainEntries, nil
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
