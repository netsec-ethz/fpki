package util

import (
	"testing"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/stretchr/testify/require"
)

func TestExtractCertDomains(t *testing.T) {
	z, err := NewGzipReader("../../tests/testdata/certs.pem.gz")
	require.NoError(t, err)
	r := NewCertReader(z)

	certs := make([]*ctx509.Certificate, 5)
	n, err := r.Read(certs)
	require.NoError(t, err)
	require.Equal(t, len(certs), n)
	names := [][]string{
		{"instaally.com", "www.instaally.com"},
		{"secure.jaymanufacturing.com"},
		{"*.ibm.xtify.com", "ibm.xtify.com"},
		{"flowers-to-the-world.com"},
		{"www.knocknok-fashion.com","knocknok-fashion.com"},
	}
	for i, names := range names {
		require.EqualValues(t, names, ExtractCertDomains(certs[i]))
	}
}
