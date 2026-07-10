package mysql

import (
	"context"
	"fmt"

	"github.com/netsec-ethz/fpki/pkg/common"
)

// InsertCRLURLs adds the given CRL distribution point URLs to the deduplicated CRL URL set.
// Existing URLs (and any mapserver-tracked state such as last_checked_at) are left untouched,
// except for last_seen_at, which is bumped to the current time on every call that references them.
func (c *mysqlDB) InsertCRLURLs(ctx context.Context, urls []string) error {
	if len(urls) == 0 {
		return nil
	}

	// Dedup defensively; callers already dedup, but keep this self-contained.
	set := make(map[string]struct{}, len(urls))
	for _, u := range urls {
		set[u] = struct{}{}
	}

	str := "INSERT INTO crl_urls (url_hash, url) VALUES " + repeatStmt(len(set), 2) +
		" ON DUPLICATE KEY UPDATE last_seen_at = CURRENT_TIMESTAMP"
	data := make([]interface{}, 0, 2*len(set))
	for u := range set {
		data = append(data, common.SHA256Hash([]byte(u)), u)
	}

	if _, err := c.db.ExecContext(ctx, str, data...); err != nil {
		return fmt.Errorf("inserting CRL urls into crl_urls table: %w", err)
	}
	return nil
}
