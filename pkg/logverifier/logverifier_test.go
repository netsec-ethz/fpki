package logverifier

import (
	"testing"

	"github.com/google/trillian"
	"github.com/google/trillian/types"
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/stretchr/testify/require"
)

func TestVerification(t *testing.T) {
	proof := &trillian.Proof{}
	err := common.JsonFileToProof(proof, "./testdata/POI.json")
	require.NoError(t, err)

	sth := &types.LogRootV1{}
	err = common.JsonFileToSTH(sth, "./testdata/STH.json")
	require.NoError(t, err)

	logverifier := NewLogVerifier(nil)

	rpc := &common.RPC{}
	err = common.JsonFileToRPC(rpc, "./testdata/rpc.json")
	require.NoError(t, err)

	rpcByes, err := common.JsonStrucToBytes(rpc)
	require.NoError(t, err)

	rpcHash := logverifier.HashLeaf(rpcByes)

	err = logverifier.VerifyInclusionByHash(sth, rpcHash, []*trillian.Proof{proof})
	require.NoError(t, err)
}

func TestConsistencyBetweenSTH(t *testing.T) {
	sth := &types.LogRootV1{}
	err := common.JsonFileToSTH(sth, "./testdata/STH.json")
	require.NoError(t, err)

	newSTH := &types.LogRootV1{}
	err = common.JsonFileToSTH(newSTH, "./testdata/NewSTH.json")
	require.NoError(t, err)

	logverifier := NewLogVerifier(nil)

	consistencyProof := [][]byte{{64, 106, 6, 19, 34, 220, 83, 247, 215, 32, 162, 107, 246, 239, 177, 77, 169, 60, 41, 70, 230, 0, 241, 108,
		241, 160, 11, 86, 200, 221, 122, 120}}

	_, err = logverifier.VerifyRoot(sth, newSTH, consistencyProof)
	require.NoError(t, err)
}

func TestProveWithOldSTH(t *testing.T) {
	proof := &trillian.Proof{}
	err := common.JsonFileToProof(proof, "./testdata/POI.json")
	require.NoError(t, err)

	sth := &types.LogRootV1{}
	err = common.JsonFileToSTH(sth, "./testdata/STH.json")
	require.NoError(t, err)

	newSTH := &types.LogRootV1{}
	err = common.JsonFileToSTH(newSTH, "./testdata/NewSTH.json")
	require.NoError(t, err)

	logverifier := NewLogVerifier(nil)

	rpc := &common.RPC{}
	err = common.JsonFileToRPC(rpc, "./testdata/rpc.json")
	require.NoError(t, err)

	rpcByes, err := common.JsonStrucToBytes(rpc)
	require.NoError(t, err)

	rpcHash := logverifier.HashLeaf(rpcByes)

	consistencyProof := [][]byte{{64, 106, 6, 19, 34, 220, 83, 247, 215, 32, 162, 107, 246, 239, 177, 77, 169, 60, 41, 70, 230, 0, 241, 108,
		241, 160, 11, 86, 200, 221, 122, 120}}

	err = logverifier.VerifyInclusionWithPrevLogRoot(sth, newSTH, consistencyProof, rpcHash, []*trillian.Proof{proof})
	require.NoError(t, err)
}
