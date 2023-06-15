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

	// Create a mock STH with the correct root hash to pass the test.
	sth := &types.LogRootV1{
		TreeSize:       2,
		RootHash:       tests.MustDecodeBase64(t, "/Pk2HUaMxp2JDmKrEw8H/vqhjs3xsUcU2JUDaDD+bDE="),
		TimestampNanos: 1661986742112252000,
		Revision:       0,
		Metadata:       []byte{},
	}

	// Mock up a RPC.
	rpc := random.RandomRPC(t)

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
		RootHash:       tests.MustDecodeBase64(t, "QxOQbyfff8Hi5UWqpLC0abhJzpQC3a+6kMgD5nepfCA="),
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
	rpc := random.RandomRPC(t)
	rpc.SPTs = []common.SPT{
		{
			AddedTS: util.TimeFromSecs(99),
			STH:     serializedSTH,
			PoI:     serializedPoI,
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
		RootHash:       tests.MustDecodeBase64(t, "p/zmpyI3xc064LO9NvXi99BqQoCQPO7GeMgzrBlAUKM="),
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
	sp := random.RandomSP(t)
	sp.SPTs = []common.SPT{
		{
			AddedTS: util.TimeFromSecs(444),
			STH:     serializedSTH,
			PoI:     serializedPoI,
		},
	}

	// Check VerifySP works.
	logverifier := NewLogVerifier(nil)
	err = logverifier.VerifySP(sp)
	require.NoError(t, err)
}
