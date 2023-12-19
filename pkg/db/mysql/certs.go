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

// RetrieveCertificatePayloads returns the payload for each certificate identified by the IDs
// parameter, in the same order (element i corresponds to IDs[i]).
func (c *mysqlDB) RetrieveCertificatePayloads(ctx context.Context, IDs []*common.SHA256Output,
) ([][]byte, error) {

	str := "SELECT cert_id,payload from certs WHERE cert_id IN " + repeatStmt(1, len(IDs))
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

// LastCTlogServerState returns the last state of the server written into the DB.
// The url specifies the CT log server from which this data comes from.
func (c *mysqlDB) LastCTlogServerState(ctx context.Context, url string,
) (size int64, sth []byte, err error) {

	size = 0
	str := "SELECT size, sth FROM ctlog_server_last_status WHERE url_hash = ?"
	err = c.db.QueryRowContext(ctx, str, common.SHA256Hash([]byte(url))).Scan(&size, &sth)
	if err == sql.ErrNoRows {
		err = nil
	}
	return
}

// UpdateLastCTlogServerState updates the index of the last certificate written into the DB.
// The url specifies the CT log server from which this index comes from.
func (c *mysqlDB) UpdateLastCTlogServerState(ctx context.Context, url string,
	size int64, sth []byte) error {

	str := "REPLACE INTO ctlog_server_last_status (url_hash, size, sth) VALUES (?,?,?)"
	_, err := c.db.ExecContext(ctx, str, common.SHA256Hash([]byte(url)), size, sth)
	return err
}

// PruneCerts removes all certificates that are no longer valid according to the paramter.
// I.e. any certificate whose NotAfter date is equal or before the parameter.
func (c *mysqlDB) PruneCerts(ctx context.Context, now time.Time) error {
	return c.pruneCerts(ctx, now)
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

	// The id_placeholders list contains strings that allow an ID to be placed with a sequential
	// number, so that the IDs are returned in the same order in the DB engine as they are present
	// in the list parameter here.
	id_placeholders := make([]string, len(data))
	for i := range id_placeholders {
		id_placeholders[i] = fmt.Sprintf("SELECT ? AS cert_id, %d AS list_seq", i)
	}

	// The query means: join two tables, one with the values I am passing as arguments (those
	// are the ids) and the certs table, and for those that exist write a 1, otherwise a 0.
	// Finally, group_concat all rows into just one field of type string.
	str := "SELECT GROUP_CONCAT(presence SEPARATOR '') FROM (" +
		"SELECT (CASE WHEN certs.cert_id IS NOT NULL THEN 1 ELSE 0 END) AS presence FROM (" +
		"SELECT cert_id FROM(" +
		strings.Join(id_placeholders, " UNION ALL ") +
		") AS sorted_by_list_seq ORDER BY list_seq" +
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

func (c *mysqlDB) pruneCerts(ctx context.Context, now time.Time) error {
	// A certificate is valid if its NotAfter is greater or equal than now.
	// We thus look for certificates with expiration less than now.

	str := "CALL prune_expired(?)"
	_, err := c.db.ExecContext(ctx, str, now)
	return err
}
