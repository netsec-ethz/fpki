package util

import (
	"crypto/rsa"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRSAPublicToPEMAndBack(t *testing.T) {
	privateKeyPair, err := rsa.GenerateKey(rand.New(rand.NewSource(0)), 2048)
	require.NoError(t, err)

	bytes, err := RSAPublicToPEM(&privateKeyPair.PublicKey)
	require.NoError(t, err)

	pubKey, err := PEMToRSAPublic(bytes)
	require.NoError(t, err)

	require.Equal(t, privateKeyPair.PublicKey, *pubKey)
}
