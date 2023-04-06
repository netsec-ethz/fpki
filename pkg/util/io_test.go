package util

import (
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
