package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
)

func (c *mysqlDB) MarkDescendentPolicyDomainsAsDirty(ctx context.Context, immutableIDs []*common.SHA256Output) error {
	if len(immutableIDs) == 0 {
		return nil
	}

	id_placeholders := make([]string, len(immutableIDs))
	for i := range id_placeholders {
		id_placeholders[i] = "SELECT ? AS immutable_policy_id"
	}
	str :=
		// mark domain IDs that need to be updated in the dirty table
		"REPLACE INTO dirty (domain_id) " +
			// select the domain IDs,
			"SELECT DISTINCT domain_policies.domain_id " +
			"FROM domain_policies " +
			// which correspond to the policy IDs,
			"INNER JOIN policies ON domain_policies.policy_id = policies.policy_id " +
			// which correspond to the immutable policy IDs
			"INNER JOIN (" +
			// recursive query that walks from each issuer policy (which is identified via its
			// immutable ID) to all of its descendants. Need index on policies.immutable_parent_id
			// to do this efficiently.
			"WITH RECURSIVE cte AS (" +
			// base case (all immutable IDs that will be updated)
			strings.Join(id_placeholders, " UNION ALL ") +
			" UNION DISTINCT " +
			// recursive case (all child policies)
			"SELECT policies.immutable_policy_id " +
			"FROM policies " +
			"INNER JOIN cte " +
			"ON policies.immutable_parent_id = cte.immutable_policy_id) " +
			"SELECT immutable_policy_id FROM cte " +
			") AS descendants ON policies.immutable_policy_id = descendants.immutable_policy_id"

	params := make([]any, len(immutableIDs))
	for i, id := range immutableIDs {
		params[i] = id[:]
	}
	_, err := c.db.QueryContext(ctx, str, params...)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("MarkDescendentPolicyDomainsAsDirty | %w", err)
	}
	return nil
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

	// The id_placeholders list contains strings that allow an ID to be placed with a sequential
	// number, so that the IDs are returned in the same order in the DB engine as they are present
	// in the list parameter here.
	id_placeholders := make([]string, len(data))
	for i := range id_placeholders {
		id_placeholders[i] = fmt.Sprintf("SELECT ? AS policy_id, %d AS list_seq", i)
	}

	// The query means: join two tables, one with the values I am passing as arguments (those
	// are the ids) and the policies table, and for those that exist write a 1, otherwise a 0.
	// Finally, group_concat all rows into just one field of type string.
	str := "SELECT GROUP_CONCAT(presence SEPARATOR '') FROM (" +
		"SELECT (CASE WHEN policies.policy_id IS NOT NULL THEN 1 ELSE 0 END) AS presence FROM (" +
		"SELECT policy_id FROM(" +
		strings.Join(id_placeholders, " UNION ALL ") +
		") AS sorted_by_list_seq ORDER BY list_seq" +
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

func (c *mysqlDB) UpdatePolicies(ctx context.Context, ids, immutableIDs, parents []*common.SHA256Output,
	expirations []*time.Time, payloads [][]byte) error {

	if len(ids) == 0 {
		return nil
	}
	// TODO(juagargi) set a prepared statement in constructor
	// Because the primary key is the SHA256 of the payload, if there is a clash, it must
	// be that the certificates are identical. Thus always REPLACE or INSERT IGNORE.
	const N = 5
	str := "REPLACE INTO policies (policy_id, immutable_policy_id, immutable_parent_id, expiration, payload) VALUES " +
		repeatStmt(len(ids), N)
	data := make([]interface{}, N*len(ids))
	for i := range ids {
		data[i*N] = ids[i][:]
		data[i*N+1] = immutableIDs[i][:]
		if parents[i] != nil {
			data[i*N+2] = parents[i][:]
		}
		data[i*N+3] = expirations[i]
		data[i*N+4] = payloads[i]
	}
	_, err := c.db.ExecContext(ctx, str, data...)
	if err != nil {
		return err
	}

	return nil
}

// UpdateDomainPolicies updates the domain_policies table.
func (c *mysqlDB) UpdateDomainPolicies(ctx context.Context,
	domainIDs, policyIDs []*common.SHA256Output) error {

	if len(domainIDs) == 0 {
		return nil
	}
	// Insert into domain_policies:
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

func (c *mysqlDB) RetrieveDomainPoliciesIDs(ctx context.Context, domainID common.SHA256Output,
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

// RetrievePolicyPayloads returns the payload for each policy identified by the IDs
// parameter, in the same order (element i corresponds to IDs[i]).
func (c *mysqlDB) RetrievePolicyPayloads(ctx context.Context, IDs []*common.SHA256Output,
) ([][]byte, error) {

	str := "SELECT policy_id,payload from policies WHERE policy_id IN " +
		repeatStmt(1, len(IDs))
	params := make([]any, len(IDs))
	for i, id := range IDs {
		params[i] = id[:]
	}
	rows, err := c.db.QueryContext(ctx, str, params...)
	if err != nil {
		return nil, err
	}

	m := make(map[common.SHA256Output][]byte, len(IDs))
	for rows.Next() {
		var id, payload []byte
		if err := rows.Scan(&id, &payload); err != nil {
			return nil, err
		}
		idArray := (*common.SHA256Output)(id)
		m[*idArray] = payload
	}

	// Sort them in the same order as the IDs.
	payloads := make([][]byte, len(IDs))
	for i, id := range IDs {
		payloads[i] = m[*id]
	}

	return payloads, nil
}
