package util

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtractCertDomains(t *testing.T) {
	raw, err := ReadAllGzippedFile("../../tests/testdata/certs.pem.gz")
	require.NoError(t, err)
	certs, err := LoadCertsFromPEMBuffer(raw)
	require.NoError(t, err)
	names := [][]string{
		{"instaally.com", "www.instaally.com"},
		{"a.com"},
	}
	_ = certs
	for i, names := range names {
		require.EqualValues(t, names, ExtractCertDomains(certs[i]))
	}
}
