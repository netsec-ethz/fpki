package logverifier

import (
	"math/rand"
	"testing"

	"github.com/google/trillian"
	"github.com/google/trillian/types"
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/netsec-ethz/fpki/pkg/tests/random"
	"github.com/netsec-ethz/fpki/pkg/util"

	"github.com/stretchr/testify/require"
)

func TestVerifyInclusionByHash(t *testing.T) {
	// Because we are using "random" bytes deterministically here, set a fixed seed.
	rand.Seed(1)

	// Create a mock proof.
	proof := &trillian.Proof{
		Hashes: [][]byte{
			tests.MustDecodeBase64(t, "RCW7/AbelL3TNWgMot/jsSAUfvxIepMGEZNqvcZTJuw="),
		},
	}

	// Create a mock STH with the correct root hash.
	sth := &types.LogRootV1{
		TreeSize:       2,
		RootHash:       tests.MustDecodeBase64(t, "BSH/yAK1xdSSNMxzNbBD4pdAsqUin8L3st6w9su+nRk="),
		TimestampNanos: 1661986742112252000,
		Revision:       0,
		Metadata:       []byte{},
	}

	// Mock up a RPC.
	rpc := &common.RPC{
		PolicyObjectBase: common.PolicyObjectBase{
			RawSubject: "fpki.com",
		},
		SerialNumber: 2,
		Version:      1,
		PublicKey:    random.RandomBytesForTest(t, 32),
		NotBefore:    util.TimeFromSecs(42),
		NotAfter:     util.TimeFromSecs(142),
		CAName:       "pca",
		TimeStamp:    util.TimeFromSecs(100),
		CASignature:  random.RandomBytesForTest(t, 32),
	}

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

func TestCheckRPC(t *testing.T) {
	// Because we are using "random" bytes deterministically here, set a fixed seed.
	rand.Seed(1)

	// Mock a STH with the right root hash.
	sth := &types.LogRootV1{
		TreeSize:       2,
		RootHash:       tests.MustDecodeBase64(t, "qtkcR3q27tgl90D5Wl1yCRYPEcvXcDvqEi1HH1mnffg="),
		TimestampNanos: 1661986742112252000,
		Revision:       0,
		Metadata:       []byte{},
	}
	serializedSTH, err := common.ToJSON(sth)
	require.NoError(t, err)

	// Mock a PoI.
	poi := []*trillian.Proof{
		{
			LeafIndex: 1,
			Hashes:    [][]byte{random.RandomBytesForTest(t, 32)},
		},
	}
	serializedPoI, err := common.ToJSON(poi)
	require.NoError(t, err)

	// Mock a RPC.
	rpc := &common.RPC{
		PolicyObjectBase: common.PolicyObjectBase{
			RawSubject: "fpki.com",
		},
		SerialNumber: 2,
		Version:      1,
		PublicKey:    random.RandomBytesForTest(t, 32),
		NotBefore:    util.TimeFromSecs(42),
		NotAfter:     util.TimeFromSecs(142),
		CAName:       "pca",
		TimeStamp:    util.TimeFromSecs(100),
		CASignature:  random.RandomBytesForTest(t, 32),
		SPTs: []common.SPT{
			{
				AddedTS: util.TimeFromSecs(99),
				STH:     serializedSTH,
				PoI:     serializedPoI,
			},
		},
	}

	// Check VerifyRPC.
	logverifier := NewLogVerifier(nil)
	err = logverifier.VerifyRPC(rpc)
	require.NoError(t, err)
}

func TestCheckSP(t *testing.T) {
	// Because we are using "random" bytes deterministically here, set a fixed seed.
	rand.Seed(3)

	// Mock a STH with the right root hash.
	sth := &types.LogRootV1{
		TreeSize:       2,
		RootHash:       tests.MustDecodeBase64(t, "8rAPQQeydFrBYHkreAlISGoGeHXFLlTqWM8Xb0wJNiY="),
		TimestampNanos: 1661986742112252000,
		Revision:       0,
		Metadata:       []byte{},
	}
	serializedSTH, err := common.ToJSON(sth)
	require.NoError(t, err)

	// Mock a PoI.
	poi := []*trillian.Proof{
		{
			LeafIndex: 1,
			Hashes:    [][]byte{random.RandomBytesForTest(t, 32)},
		},
	}
	serializedPoI, err := common.ToJSON(poi)
	require.NoError(t, err)

	// Mock an SP.
	sp := &common.SP{
		PolicyObjectBase: common.PolicyObjectBase{
			RawSubject: "fpki.com",
		},
		Policies: common.Policy{
			TrustedCA: []string{"US CA"},
		},
		TimeStamp:         util.TimeFromSecs(444),
		CAName:            "pca",
		SerialNumber:      4,
		CASignature:       random.RandomBytesForTest(t, 32),
		RootCertSignature: random.RandomBytesForTest(t, 32),
		SPTs: []common.SPT{
			{
				AddedTS: util.TimeFromSecs(444),
				STH:     serializedSTH,
				PoI:     serializedPoI,
			},
		},
	}

	// Check VerifySP works.
	logverifier := NewLogVerifier(nil)
	err = logverifier.VerifySP(sp)
	require.NoError(t, err)
}
