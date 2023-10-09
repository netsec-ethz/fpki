package util

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewGzipReader(t *testing.T) {
	r, err := NewGzipReader("../../tests/testdata/certs.pem.gz")
	require.NoError(t, err)

	// Read 10 bytes (the file is much bigger).
	var buff [10]byte
	n, err := r.Read(buff[:])
	require.NoError(t, err)
	require.Equal(t, len(buff), n)

	err = r.Close()
	require.NoError(t, err)
}

// TestCertificateFromPEMFile checks that the CertificateFromPEMFile loads a regular x509 Cert.
func TestCertificateFromPEMFile(t *testing.T) {
	cert, err := CertificateFromPEMFile("../../tests/testdata/1-regular-cert.pem")
	require.NoError(t, err)

	result := ExtractCertDomains(cert)
	require.ElementsMatch(t, result, []string{"*.adiq.com.br", "adiq.com.br"})
}

func TestRSAKeyFromPEMFileAndBack(t *testing.T) {
	filename := "../../tests/testdata/clientkey.pem"
	expectedPEM, err := os.ReadFile(filename)
	require.NoError(t, err)

	key, err := RSAKeyFromPEMFile(filename)
	require.NoError(t, err, "load RSA key error")

	gotPEM := RSAKeyToPEM(key)
	// Compare against bytes in file.
	require.Equal(t, expectedPEM, gotPEM)
}
