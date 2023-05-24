package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
)

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
