package main

import (
	"context"
	"testing"
	"time"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"go.uber.org/mock/gomock"

	"github.com/stretchr/testify/require"

	"github.com/netsec-ethz/fpki/pkg/db/mock_db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	"github.com/netsec-ethz/fpki/pkg/tests/testdb"
)

func TestRecordCRLURLs(t *testing.T) {
	w := NewLineToChainWorker(&Processor{}, 0)

	w.recordCRLURLs(&ctx509.Certificate{
		CRLDistributionPoints: []string{"http://a.example.com/1.crl", "http://a.example.com/2.crl"},
	})
	w.recordCRLURLs(&ctx509.Certificate{
		CRLDistributionPoints: []string{"http://a.example.com/2.crl"}, // duplicate, must not add a new entry.
	})
	w.recordCRLURLs(&ctx509.Certificate{}) // no CRLDistributionPoints at all.

	require.Equal(t, map[string]struct{}{
		"http://a.example.com/1.crl": {},
		"http://a.example.com/2.crl": {},
	}, w.crlURLs)
}

func TestFlushCRLURLsMergesWorkers(t *testing.T) {
	ctrl := gomock.NewController(t)
	conn := mock_db.NewMockConn(ctrl)

	var gotURLs []string
	conn.EXPECT().
		InsertCRLURLs(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, urls []string) error {
			gotURLs = urls
			return nil
		})

	p := &Processor{
		Manager: &updater.Manager{Conn: conn},
		toChainWorkers: []*lineToChainWorker{
			{crlURLs: map[string]struct{}{"url1": {}, "url2": {}}},
			{crlURLs: map[string]struct{}{"url2": {}, "url3": {}}}, // url2 overlaps across workers.
		},
	}

	require.NoError(t, p.FlushCRLURLs(context.Background()))
	require.ElementsMatch(t, []string{"url1", "url2", "url3"}, gotURLs)
}

func TestFlushCRLURLs_NoURLs(t *testing.T) {
	ctrl := gomock.NewController(t)
	conn := mock_db.NewMockConn(ctrl) // No calls expected on it.

	p := &Processor{
		Manager:        &updater.Manager{Conn: conn},
		toChainWorkers: []*lineToChainWorker{{crlURLs: map[string]struct{}{}}},
	}

	require.NoError(t, p.FlushCRLURLs(context.Background()))
}

func TestFlushCRLURLsEndToEnd(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelF()

	config, removeF := testdb.ConfigureTestDB(t)
	defer removeF()
	conn := testdb.Connect(t, config)
	defer conn.Close()

	p := &Processor{
		Manager: &updater.Manager{Conn: conn},
		toChainWorkers: []*lineToChainWorker{
			{crlURLs: map[string]struct{}{"http://example.com/a.crl": {}}},
			{crlURLs: map[string]struct{}{"http://example.com/b.crl": {}}},
		},
	}

	require.NoError(t, p.FlushCRLURLs(ctx))

	var count int
	require.NoError(t, conn.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM crl_urls").Scan(&count))
	require.Equal(t, 2, count)
}
