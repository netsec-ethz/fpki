package tests

import (
	"encoding/base64"
	"encoding/hex"

	"github.com/stretchr/testify/require"
)

// MustDecodeString decodes the string using hex.DecodeString or fails the test.
func MustDecodeString(t T, s string) []byte {
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// MustDecodeBase64 decodes the base64 string using base64.StdEncoding.DecodeString or fails
// the test.
func MustDecodeBase64(t T, s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	require.NoError(t, err)
	return b
}
