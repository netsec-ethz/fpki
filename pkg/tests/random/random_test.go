package random_test

import (
	"math/rand"
	"testing"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/stretchr/testify/require"

	"github.com/netsec-ethz/fpki/pkg/common"
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

func TestRandomX509Cert(t *testing.T) {
	c1 := random.RandomX509Cert(t, "a.com")
	require.NotEmpty(t, c1.Raw)
	cert, err := ctx509.ParseCertificate(c1.Raw)
	require.NoError(t, err)
	require.Equal(t, cert.Raw, c1.Raw)

	c2 := random.RandomX509Cert(t, "a.com")
	require.NotEmpty(t, c2.Raw)
	require.NotEqual(t, c1.Raw, c2.Raw)

	// Sizes not too big. Usual certificates are < 4K.
	require.Less(t, len(c1.Raw), 1024)
	require.Less(t, len(c2.Raw), 1024)
}

// TestBuildTestRandomCertHierarchy checks that the function creates two leaf certificates with
// their chains.
// The two chains are leaf->c1.com->c0.com, and leaf->c0.com
// There are only 4 certificate objects created, thus c0 is common to both chains.
func TestBuildTestRandomCertHierarchy(t *testing.T) {
	leafs := []string{
		"a.com",
		"b.com",
	}
	var certs []*ctx509.Certificate
	var certIDs, parentCertIDs []*common.SHA256Output
	var certNames [][]string
	nonLeafCerts := make([]*ctx509.Certificate, 0, len(certs)/2)
	for _, leaf := range leafs {
		certs2, certIDs2, parentCertIDs2, certNames2 := random.BuildTestRandomCertHierarchy(t, leaf)

		// Check sizes
		require.Equal(t, 4, len(certs2))
		require.Equal(t, len(certs2), len(certIDs2))
		require.Equal(t, len(certs2), len(parentCertIDs2))
		require.Equal(t, len(certs2), len(certNames2))

		// Check positions:
		// [0] c0.com
		// [1] c1.com
		// [2] leaf->c1->c0
		// [3] leaf->c0

		// Names
		require.Equal(t, "c0.com", certs2[0].Subject.CommonName)
		require.Equal(t, "c1.com", certs2[1].Subject.CommonName)
		require.Equal(t, leaf, certs2[2].Subject.CommonName)
		require.Equal(t, leaf, certs2[3].Subject.CommonName)

		// Parents
		nilPtr := (*common.SHA256Output)(nil)
		require.Equal(t, nilPtr, parentCertIDs2[0])      // parent(c0)=nil
		require.Equal(t, certIDs2[0], parentCertIDs2[1]) // parent(c1)=c0
		require.Equal(t, certIDs2[1], parentCertIDs2[2]) // parent(leaf1)=c1
		require.Equal(t, certIDs2[0], parentCertIDs2[3]) // parent(leaf2)=c0

		nonLeafCerts = append(nonLeafCerts, certs2[0], certs2[1])

		certs = append(certs, certs2...)
		certIDs = append(certIDs, certIDs2...)
		parentCertIDs = append(parentCertIDs, parentCertIDs2...)
		certNames = append(certNames, certNames2...)
	}

	require.Equal(t, 4*len(leafs), len(certs))
	require.Equal(t, len(certs), len(certIDs))
	require.Equal(t, len(certs), len(parentCertIDs))
	require.Equal(t, len(certs), len(certNames))

	// No cert in certs is duplicated other than the leaves.
	uniqueCerts := make(map[[32]byte]struct{})
	for _, c := range nonLeafCerts {
		sha := common.SHA256Hash32Bytes(c.Raw)
		// require.NotContains(t, uniqueCerts, sha)
		if _, ok := uniqueCerts[sha]; ok {
			require.FailNowf(t, "duplicated cert", "common name %s", c.Subject.CommonName)
		}
		uniqueCerts[sha] = struct{}{}
	}
}
