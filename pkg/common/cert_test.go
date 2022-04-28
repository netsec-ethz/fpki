package common

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/require"
)

// TODO: more unit tests

// Test_Enc_And_Dec_Of_PubKey public key -> bytes -> public key
func Test_Enc_And_Dec_Of_PubKey(t *testing.T) {
	privateKeyPair, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	bytes, err := RsaPublicKeyToPemBytes(&privateKeyPair.PublicKey)
	require.NoError(t, err, "encoding error")

	pubKey, err := PemBytesToRsaPublicKey(bytes)
	require.NoError(t, err, "decoding error")

	require.Equal(t, privateKeyPair.PublicKey, *pubKey, "parsing error")
}
