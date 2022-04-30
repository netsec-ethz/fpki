package common

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/require"
)

// TODO(Yongzhe): more unit tests

// TestEncAndDecOfPubKey public key -> bytes -> public key
func TestEncAndDecOfPubKey(t *testing.T) {
	privateKeyPair, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	bytes, err := RsaPublicKeyToPemBytes(&privateKeyPair.PublicKey)
	require.NoError(t, err, "encoding error")

	pubKey, err := PemBytesToRsaPublicKey(bytes)
	require.NoError(t, err, "decoding error")

	require.Equal(t, privateKeyPair.PublicKey, *pubKey, "parsing error")
}
