package benchmark

import (
	"compress/gzip"
	"context"
	"encoding/pem"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/netsec-ethz/fpki/pkg/domain"
	"github.com/netsec-ethz/fpki/pkg/mapserver/logfetcher"
	"github.com/stretchr/testify/require"
)

const ctURL = "https://ct.googleapis.com/logs/argon2021"

func BenchmarkDownload1K(b *testing.B) {
	benchmarkDownload(b, 1000)
}

func BenchmarkDownload10K(b *testing.B) {
	b.Skip("download skipped")
	benchmarkDownload(b, 10*1000)
}

func benchmarkDownload(b *testing.B, count int) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Duration(count)*time.Millisecond)
	defer cancelF()
	baseSize := 2 * 1000 * 1000
	// exec only once, assume perfect measuring. Because b.N is the number of iterations,
	// just mimic b.N executions.
	fetcher := logfetcher.LogFetcher{
		URL:         ctURL,
		Start:       baseSize,
		End:         baseSize + count,
		WorkerCount: 20,
	}
	t0 := time.Now()
	_, err := fetcher.FetchAllCertificates(ctx)
	elapsed := time.Since(t0)
	require.NoError(b, err)
	for i := 1; i < b.N; i++ {
		time.Sleep(elapsed)
	}
}

func TestCreateCerts(t *testing.T) {
	if os.Getenv("FPKI_TESTS_GENCERTS") == "" {
		t.Skip("not generating new certificates")
	}
	ctx, cancelF := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancelF()
	baseSize := 2 * 1000
	count := 100 * 1000
	fetcher := logfetcher.LogFetcher{
		URL:         ctURL,
		Start:       baseSize,
		End:         baseSize + count - 1,
		WorkerCount: 32,
	}
	certs, err := fetcher.FetchAllCertificates(ctx)
	require.NoError(t, err)
	require.Len(t, certs, count, "we have %d certificates", len(certs))

	f, err := os.Create("../../testdata/certs.pem.gz")
	require.NoError(t, err)
	z, err := gzip.NewWriterLevel(f, gzip.BestCompression)
	require.NoError(t, err)
	uniqueNames := make(map[string]struct{})
	for _, c := range certs {
		require.NotNil(t, c.RawTBSCertificate)
		err = pem.Encode(z, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.RawTBSCertificate,
		})
		require.NoError(t, err)

		uniqueNames[c.Subject.CommonName] = struct{}{}
	}
	err = z.Close()
	require.NoError(t, err)
	err = f.Close()
	require.NoError(t, err)

	// write the list of unique names
	names := make([]string, 0, len(uniqueNames))
	for n := range uniqueNames {
		if domain.IsValidDomain(n) {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	f, err = os.Create("../../testdata/uniqueNames.txt")
	require.NoError(t, err)
	for _, n := range names {
		_, err = f.WriteString(n + "\n")
		require.NoError(t, err)
	}
	err = f.Close()
	require.NoError(t, err)
}
