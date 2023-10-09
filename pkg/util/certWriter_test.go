package util

import (
	"bytes"
	"os"
	"testing"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/stretchr/testify/require"
)

func TestCertWriter(t *testing.T) {
	payload, err := os.ReadFile("../../tests/testdata/3-certs.pem")
	require.NoError(t, err)
	// Load three certificates.
	N := 3
	r := NewCertReader(bytes.NewBuffer(payload))
	certs := make([]*ctx509.Certificate, N)
	n, err := r.Read(certs)
	require.NoError(t, err)
	require.Equal(t, N, n)

	// Write them.
	buff := bytes.NewBuffer(nil)
	w := NewCertWriter(buff)
	n, err = w.Write(certs)
	require.NoError(t, err)
	require.Equal(t, N, n)

	// Compare payloads
	require.Equal(t, payload, buff.Bytes())
}
