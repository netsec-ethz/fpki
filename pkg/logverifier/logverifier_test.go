package logverifier

import (
	"math/rand"
	"testing"

	"github.com/google/trillian"
	"github.com/google/trillian/types"
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/common/crypto"
	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/netsec-ethz/fpki/pkg/tests/random"
	"github.com/netsec-ethz/fpki/pkg/util"

	"github.com/stretchr/testify/require"
)

func TestVerifySPT(t *testing.T) {
	ownwerPriv, err := util.RSAKeyFromPEMFile("../../tests/testdata/clientkey.pem")
	require.NoError(t, err, "load RSA key error")
	issuerPriv, err := util.RSAKeyFromPEMFile("../../tests/testdata/serverkey.pem")
	require.NoError(t, err, "load RSA key error")

	req := random.RandomPolCertSignRequest(t)
	err = crypto.SignAsOwner(ownwerPriv, req)
	require.NoError(t, err)

	cert, err := crypto.SignRequestAsIssuer(req, issuerPriv)
	require.NoError(t, err)
	_ = cert
}

func TestVerifyInclusionByHash(t *testing.T) {
	// Because we are using "random" bytes deterministically here, set a fixed seed.
	rand.Seed(1)

	// Create a mock proof.
	proof := &trillian.Proof{
		Hashes: [][]byte{
			tests.MustDecodeBase64(t, "RCW7/AbelL3TNWgMot/jsSAUfvxIepMGEZNqvcZTJuw="),
		},
	}

	// Create a mock STH with the correct root hash to pass the test.
	sth := &types.LogRootV1{
		TreeSize:       2,
		RootHash:       tests.MustDecodeBase64(t, "VZfa96+e9du6zpvFD/ZlMFMiTqfruk71mqzcg+NG350="),
		TimestampNanos: 1661986742112252000,
		Revision:       0,
		Metadata:       []byte{},
	}

	// Mock up a RPC.
	rpc := random.RandomPolicyCertificate(t)

	// Serialize it without SPTs.
	serializedRPC, err := common.ToJSON(rpc)
	require.NoError(t, err, "Json Struct To Bytes Error")

	// New log verifier and hash the RPC.
	logverifier := NewLogVerifier(nil)
	rpcHash := logverifier.HashLeaf(serializedRPC)

	// Check that VerifyInclusionByHash works:
	err = logverifier.VerifyInclusionByHash(sth, rpcHash, []*trillian.Proof{proof})
	require.NoError(t, err, "Verify Inclusion By Hash Error")
}

// TestConsistencyBetweenSTH checks that two STHs are consistently sequential by using VerifyRoot.
func TestConsistencyBetweenSTH(t *testing.T) {
	sth := &types.LogRootV1{
		Revision:       0,
		TreeSize:       2,
		TimestampNanos: 1651518756445580000,
		RootHash:       tests.MustDecodeBase64(t, "qVKbXMndXP7Pd+rJm9NuUsgENjgXeMgf9CsXtmNxtxM="),
		Metadata:       []byte{},
	}

	newSTH := &types.LogRootV1{
		Revision:       0,
		TreeSize:       3,
		TimestampNanos: 1651518756732994000,
		RootHash:       tests.MustDecodeBase64(t, "ua6XccS1nESMgxBA3gh+pfAI9DgIrPD6o1Ib7gXS4fI="),
		Metadata:       []byte{},
	}

	consistencyProof := [][]byte{
		tests.MustDecodeBase64(t, "QGoGEyLcU/fXIKJr9u+xTak8KUbmAPFs8aALVsjdeng="),
	}

	logverifier := NewLogVerifier(nil)
	_, err := logverifier.VerifyRoot(sth, newSTH, consistencyProof)
	require.NoError(t, err, "Verify Root Error")
}
