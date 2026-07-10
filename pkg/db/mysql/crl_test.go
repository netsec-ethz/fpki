package mysql_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netsec-ethz/fpki/pkg/tests/testdb"
)

func TestInsertCRLURLs(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelF()

	config, removeF := testdb.ConfigureTestDB(t)
	defer removeF()

	conn := testdb.Connect(t, config)
	defer conn.Close()

	// Inserting an empty slice must be a no-op.
	require.NoError(t, conn.InsertCRLURLs(ctx, nil))

	url1 := "http://example-ca.com/crl/1.crl"
	url2 := "http://example-ca.com/crl/2.crl"

	// Insert a set with a duplicate; only one row per unique URL should land.
	require.NoError(t, conn.InsertCRLURLs(ctx, []string{url1, url2, url1}))

	var count int
	require.NoError(t, conn.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM crl_urls").Scan(&count))
	require.Equal(t, 2, count)

	// Manually set last_checked_at on url1, as the future mapserver fetcher would.
	_, err := conn.DB().ExecContext(ctx,
		"UPDATE crl_urls SET last_checked_at = '2020-01-01 00:00:00' WHERE url = ?", url1)
	require.NoError(t, err)

	var createdAt, lastSeenAt time.Time
	require.NoError(t, conn.DB().QueryRowContext(ctx,
		"SELECT created_at, last_seen_at FROM crl_urls WHERE url = ?", url1,
	).Scan(&createdAt, &lastSeenAt))

	// Sleep to guarantee CURRENT_TIMESTAMP() advances past the previous last_seen_at.
	time.Sleep(1100 * time.Millisecond)

	// Re-insert url1 (overlapping with a previously unseen url3).
	url3 := "http://example-ca.com/crl/3.crl"
	require.NoError(t, conn.InsertCRLURLs(ctx, []string{url1, url3}))

	// Row count grows only by the genuinely new URL.
	require.NoError(t, conn.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM crl_urls").Scan(&count))
	require.Equal(t, 3, count)

	var createdAt2, lastSeenAt2 time.Time
	var lastCheckedAt time.Time
	require.NoError(t, conn.DB().QueryRowContext(ctx,
		"SELECT created_at, last_seen_at, last_checked_at FROM crl_urls WHERE url = ?", url1,
	).Scan(&createdAt2, &lastSeenAt2, &lastCheckedAt))

	// created_at and the manually-set last_checked_at must survive the re-insert...
	require.True(t, createdAt.Equal(createdAt2), "created_at must not change on re-insert")
	require.Equal(t, 2020, lastCheckedAt.Year(), "last_checked_at must not be touched by ingest")
	// ...while last_seen_at must have advanced.
	require.True(t, lastSeenAt2.After(lastSeenAt), "last_seen_at must advance on re-sighting")
}
