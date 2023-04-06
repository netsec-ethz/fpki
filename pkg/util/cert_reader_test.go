package util

import (
	"os"
	"testing"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/stretchr/testify/require"
)

func TestCertReader(t *testing.T) {
	z, err := NewGzipReader("../../tests/testdata/certs.pem.gz")
	require.NoError(t, err)

	N := 10
	certs := make([]*ctx509.Certificate, N)
	r := NewCertReader(z)
	n, err := r.Read(certs)
	require.NoError(t, err)
	require.Equal(t, N, n)
	// Close.
	require.NoError(t, z.Close())
	// Reading again should yield an error.
	n, err = r.Read(certs)
	require.Error(t, err)
	require.Less(t, n, N)
	// Open again.
	z, err = NewGzipReader("../../tests/testdata/certs.pem.gz")
	require.NoError(t, err)

	N = 10
	certs = make([]*ctx509.Certificate, N)
	r = NewCertReader(z)
	n, err = r.Read(certs)
	require.NoError(t, err)
	require.Equal(t, N, n)

	N = 20
	certs = make([]*ctx509.Certificate, N)
	r = NewCertReader(z)
	n, err = r.Read(certs)
	require.NoError(t, err)
	require.Equal(t, N, n)

	N = 5
	certs = make([]*ctx509.Certificate, N)
	r = NewCertReader(z)
	n, err = r.Read(certs)
	require.NoError(t, err)
	require.Equal(t, N, n)

	// Close and open again.
	z, err = NewGzipReader("../../tests/testdata/certs.pem.gz")
	require.NoError(t, err)
	// Read them all.
	N = 100000 - 1
	certs = make([]*ctx509.Certificate, N)
	r = NewCertReader(z)
	n, err = r.Read(certs)
	require.NoError(t, err)
	require.Equal(t, N, n)
	// Last certificate
	n, err = r.Read(certs)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	// There should be no other certificate left.
	n, err = r.Read(certs)
	require.NoError(t, err)
	require.Equal(t, 0, n)
	// Close.
	require.NoError(t, z.Close())
}

func TestCertReaderOneByOne(t *testing.T) {
	f, err := os.Open("../../tests/testdata/3-certs.pem")
	require.NoError(t, err)

	r := NewCertReader(f)
	N := 3

	cs := make([]*ctx509.Certificate, 1)
	for i := 0; i < N; i++ {
		t.Logf("iteration %d", i)
		n, err := r.Read(cs)
		require.NoError(t, err)
		require.Equal(t, 1, n)
	}

	require.NoError(t, f.Close())
}
