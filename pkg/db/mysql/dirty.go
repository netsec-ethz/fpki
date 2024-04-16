package mysql

import (
	"context"
	"fmt"

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
