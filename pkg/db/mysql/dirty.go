package mysql

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/netsec-ethz/fpki/pkg/common"
)

func (c *mysqlDB) DirtyCount(ctx context.Context) (uint64, error) {
	str := "SELECT COUNT(*) FROM dirty"
	row := c.db.QueryRowContext(ctx, str)
	if err := row.Err(); err != nil {
		return 0, fmt.Errorf("error querying dirty domains count: %w", err)
	}

	var count uint64
	if err := row.Scan(&count); err != nil {
		return 0, fmt.Errorf("error querying dirty domains count: %w", err)
	}
	return count, nil
}

// RetrieveDirtyDomains returns the domain IDs that are still dirty, i.e. modified certificates for
// that domain, but not yet coalesced and ingested by the SMT.
func (c *mysqlDB) RetrieveDirtyDomains(ctx context.Context) ([]*common.SHA256Output, error) {
	str := "SELECT domain_id FROM dirty"
	rows, err := c.db.QueryContext(ctx, str)
	if err != nil {
		return nil, fmt.Errorf("error querying dirty domains: %w", err)
	}
	domainIDs := make([]*common.SHA256Output, 0)
	for rows.Next() {
		var domainId []byte
		err = rows.Scan(&domainId)
		if err != nil {
			return nil, fmt.Errorf("error scanning domain ID: %w", err)
		}
		ptr := (*common.SHA256Output)(domainId)
		domainIDs = append(domainIDs, ptr)
	}
	return domainIDs, nil
}

func (c *mysqlDB) InsertDomainsIntoDirty(ctx context.Context, domainIDs []*common.SHA256Output) error {
	return c.insertDomainsIntoDirtyCSV(ctx, domainIDs)
}

func (c *mysqlDB) insertDomainsIntoDirtyCSV(
	ctx context.Context,
	domainIDs []*common.SHA256Output,
) error {
	// Prepare the records for the CSV file.
	records := make([][]string, len(domainIDs))
	for i := 0; i < len(domainIDs); i++ {
		records[i] = make([]string, 1)
		records[i][0] = (base64.StdEncoding.EncodeToString(domainIDs[i][:]))
	}

	// Create temporary file.
	tempfile, err := os.CreateTemp(TemporaryDir, "fpki-ingest-dirty-*.csv")
	if err != nil {
		return fmt.Errorf("creating temporary file: %w", err)
	}
	defer os.Remove(tempfile.Name())

	// Write data to CSV file.
	if err = writeToCSV(tempfile, records); err != nil {
		return err
	}

	// Now instruct MySQL to directly ingest this file into the certs table.
	if _, err := loadDirtyTableWithCSV(ctx, c.db, tempfile.Name()); err != nil {
		return fmt.Errorf("inserting CSV \"%s\" into DB.dirty: %w", tempfile.Name(), err)
	}

	return nil
}

func (c *mysqlDB) insertDomainsIntoDirtyMemory(
	ctx context.Context,
	domainIDs []*common.SHA256Output,
) error {
	// Make the list of domains unique, attach the name to each unique ID.
	domainIDsSet := make(map[common.SHA256Output]struct{})
	for _, id := range domainIDs {
		domainIDsSet[*id] = struct{}{}
	}

	str := "INSERT IGNORE INTO dirty (domain_id) VALUES " + repeatStmt(len(domainIDsSet), 1)
	data := make([]any, len(domainIDsSet))
	i := 0
	for k := range domainIDsSet {
		// Copy the 32 bytes locally here, not just the pointer or slice.
		// The loop variable k is set with 32 new bytes on each iteration, but its pointer &k does
		// not change and remains constant for all the loop ("captured"). A slice on that array
		// such as k[:] will create a new slice, with all the same storage across all iterations.
		localK := k // Because k changes during the loop, we need a local copy that doesn't.
		data[i] = localK[:]
		i++
	}

	if _, err := c.db.ExecContext(ctx, str, data...); err != nil {
		return fmt.Errorf("inserting domains into dirty: %w", err)
	}

	return nil
}

func (c *mysqlDB) CleanupDirty(ctx context.Context) error {
	// Remove all entries from the dirty table.
	str := "TRUNCATE dirty"
	_, err := c.db.ExecContext(ctx, str)
	if err != nil {
		return fmt.Errorf("error truncating dirty table: %w", err)
	}
	return nil
}

func (c *mysqlDB) RecomputeDirtyDomainsCertAndPolicyIDs(ctx context.Context) error {

	// Call the coalescing stored procedure without parameters.
	str := "CALL calc_dirty_domains()"
	_, err := c.db.ExecContext(ctx, str)
	if err != nil {
		return fmt.Errorf("coalescing for domains: %w", err)
	}
	return nil
}

func loadDirtyTableWithCSV(
	ctx context.Context,
	db *sql.DB,
	filepath string,
) (sql.Result, error) {

	// Set read permissions to all.
	if err := os.Chmod(filepath, 0644); err != nil {
		return nil, fmt.Errorf("setting permissions to file \"%s\": %w", filepath, err)
	}

	str := `LOAD DATA CONCURRENT INFILE ? IGNORE INTO TABLE dirty ` +
		`FIELDS TERMINATED BY ',' ENCLOSED BY '"' LINES TERMINATED BY '\n' ` +
		`(@domain_id) SET ` +
		`domain_id = FROM_BASE64(@domain_id);`
	return db.ExecContext(ctx, str, filepath)
}
