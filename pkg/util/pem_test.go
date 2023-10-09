package util_test

import (
	"testing"

	"github.com/netsec-ethz/fpki/pkg/tests/random"
	"github.com/netsec-ethz/fpki/pkg/util"
	"github.com/stretchr/testify/require"
)

func TestRSAPublicToDERBytesAndBack(t *testing.T) {
	privateKeyPair := random.RandomRSAPrivateKey(t)

	pubKeyDER, err := util.RSAPublicToDERBytes(&privateKeyPair.PublicKey)
	require.NoError(t, err)
	got, err := util.DERBytesToRSAPublic(pubKeyDER)
	require.NoError(t, err)
	require.Equal(t, &privateKeyPair.PublicKey, got)
}
