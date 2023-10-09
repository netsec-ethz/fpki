package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
)

const batchSize = 1000

type mysqlDB struct {
	db *sql.DB
}

// NewMysqlDB is called to create a new instance of the mysqlDB.
func NewMysqlDB(db *sql.DB) (*mysqlDB, error) {
	return &mysqlDB{
		db: db,
	}, nil
}

func (c *mysqlDB) DB() *sql.DB {
	return c.db
}

func (c *mysqlDB) Close() error {
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
