package random_test

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netsec-ethz/fpki/pkg/tests/random"
)

func TestRandomPolicyCertificate(t *testing.T) {
	rand.Seed(0)
	pc1 := random.RandomPolicyCertificate(t)
	pc2 := random.RandomPolicyCertificate(t)
	require.NotEqual(t, pc1, pc2)

	rand.Seed(0)
	gotPc1 := random.RandomPolicyCertificate(t)
	gotPc2 := random.RandomPolicyCertificate(t)
	require.Equal(t, pc1, gotPc1)
	require.Equal(t, pc2, gotPc2)
}

func TestRandomRSAPrivateKey(t *testing.T) {
	rand.Seed(0)
	k1 := random.RandomRSAPrivateKey(t)
	k2 := random.RandomRSAPrivateKey(t)
	require.NotEqual(t, k1, k2)

	rand.Seed(0)
	gotK1 := random.RandomRSAPrivateKey(t)
	gotK2 := random.RandomRSAPrivateKey(t)
	require.Equal(t, k1, gotK1)
	require.Equal(t, k2, gotK2)
}
