package benchmark

import (
	"compress/gzip"
	"encoding/pem"
	"os"
	"testing"
	"time"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/mapserver/logpicker"
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
	baseSize := 2 * 1000 * 1000
	// exec only once, assume perfect measuring. Because b.N is the number of iterations,
	// just mimic b.N executions.
	t0 := time.Now()
	_, err := logpicker.GetCertMultiThread(ctURL, int64(baseSize), int64(baseSize+count), 20)
	elapsed := time.Since(t0)
	require.NoError(b, err)
	for i := 1; i < b.N; i++ {
		time.Sleep(elapsed)
	}
}

func TestCreateCerts(t *testing.T) {
	// TODO(juagargi) there seems to be a bug in the fetcher.
	// With the same start and end values, we should get exactly the same certificates, but don't
	// https://ct.googleapis.com/logs/argon2021/ct/v1/get-entries?start=2000&end=2001&quot
	if os.Getenv("FPKI_TESTS_GENCERTS") == "" {
		t.Skip("not generating new certificates")
	}
	baseSize := 2 * 1000
	count := 100 * 1000
	certs, err := logpicker.GetCertMultiThread(ctURL, int64(baseSize), int64(baseSize+count-1), 32)
	require.NoError(t, err)
	require.Len(t, certs, count, "we have %d certificates", len(certs))

	f, err := os.Create("testdata/certs.pem.gz")
	require.NoError(t, err)
	z, err := gzip.NewWriterLevel(f, gzip.BestCompression)
	require.NoError(t, err)
	for _, c := range certs {
		require.NotNil(t, c.RawTBSCertificate)
		err = pem.Encode(z, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.RawTBSCertificate,
		})
		require.NoError(t, err)
	}
	err = z.Close()
	require.NoError(t, err)
	err = f.Close()
	require.NoError(t, err)
}

func loadCertsFromPEM(t require.TestingT, raw []byte) []*ctx509.Certificate {
	certs := make([]*ctx509.Certificate, 0)
	for len(raw) > 0 {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := ctx509.ParseTBSCertificate(block.Bytes)
		require.NoError(t, err)
		certs = append(certs, c)
	}
	return certs
}
