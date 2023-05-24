package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
)

// CheckCertsExist returns a slice of true/false values. Each value indicates if
// the corresponding certificate identified by its ID is already present in the DB.
func (c *mysqlDB) CheckCertsExist(ctx context.Context, ids []*common.SHA256Output) ([]bool, error) {
	if len(ids) == 0 {
		// If empty, return empty.
		return nil, nil
	}
	presence := make([]bool, len(ids))

	// The query won't accept more than batchSize elements. Make batches.
	for i := 0; i < len(ids)-batchSize; i += batchSize {
		to := i + batchSize
		if err := c.checkCertsExist(ctx, ids[i:to], presence[i:to]); err != nil {
			return nil, err
		}
	}
	// Do the last batch, if non empty.
	from := len(ids) / batchSize * batchSize
	to := from + len(ids)%batchSize
	var err error
	if to > from {
		err = c.checkCertsExist(ctx, ids[from:to], presence[from:to])
	}
	return presence, err
}

func (c *mysqlDB) UpdateCerts(ctx context.Context, ids, parents []*common.SHA256Output,
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

// RetrieveDomainCertificatesIDs retrieves the domain's certificate payload ID and the payload itself,
// given the domain ID.
func (c *mysqlDB) RetrieveDomainCertificatesIDs(ctx context.Context, domainID common.SHA256Output,
) (*common.SHA256Output, []byte, error) {

	str := "SELECT cert_ids_id, cert_ids FROM domain_payloads WHERE domain_id = ?"
	var certIDsID, certIDs []byte
	err := c.db.QueryRowContext(ctx, str, domainID[:]).Scan(&certIDsID, &certIDs)
	if err != nil && err != sql.ErrNoRows {
		return nil, nil, fmt.Errorf("RetrieveDomainCertificatesIDs | %w", err)
	}
	var IDptr *common.SHA256Output
	if certIDsID != nil {
		IDptr = (*common.SHA256Output)(certIDsID)
	}
	return IDptr, certIDs, nil
}

// checkCertsExist should not be called with larger than ~1000 elements, the query being used
// may fail with a message like:
// Error 1436 (HY000): Thread stack overrun:  1028624 bytes used of a 1048576 byte stack,
// and 20000 bytes needed.  Use 'mysqld --thread_stack=#' to specify a bigger stack.
func (c *mysqlDB) checkCertsExist(ctx context.Context, ids []*common.SHA256Output,
	present []bool) error {

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
	var value string
	if err := c.db.QueryRowContext(ctx, str, data...).Scan(&value); err != nil {
		return err
	}
	for i, c := range value {
		if c == '1' {
			present[i] = true
		}
	}

	return nil
}
