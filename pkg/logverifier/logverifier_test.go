package logverifier

import (
	"testing"

	"github.com/google/trillian"
	"github.com/google/trillian/types"
	"github.com/netsec-ethz/fpki/pkg/common"

	"github.com/stretchr/testify/require"
)

// TestVerification: Test logverifier.VerifyInclusionByHash()
func TestVerification(t *testing.T) {
	proof := &trillian.Proof{}

	err := common.JsonFileToProof(proof, "./testdata/POI.json")
	require.NoError(t, err, "Json File To Proof Error")

	sth, err := common.JsonBytesToLogRoot([]byte("{\"TreeSize\":2,\"RootHash\":\"VsGAf6yfqGWcEno9aRBj3O1N9E8fY/XE9nJmYKjefPM=\",\"TimestampNanos\":1661986742112252000,\"Revision\":0,\"Metadata\":\"\"}"))
	require.NoError(t, err, "Json bytes To STH Error")

	logverifier := NewLogVerifier(nil)

	rpc := &common.RPC{}
	err = common.JsonFileToRPC(rpc, "./testdata/rpc.json")
	require.NoError(t, err, "Json File To RPC Error")

	rpc.SPTs = []common.SPT{}

	rpcBytes, err := common.JsonStrucToBytes(rpc)
	require.NoError(t, err, "Json Struct To Bytes Error")

	rpcHash := logverifier.HashLeaf(rpcBytes)

	err = logverifier.VerifyInclusionByHash(sth, rpcHash, []*trillian.Proof{proof})
	require.NoError(t, err, "Verify Inclusion By Hash Error")
}

// TestConsistencyBetweenSTH: test logverifier.VerifyRoot()
func TestConsistencyBetweenSTH(t *testing.T) {
	sth := &types.LogRootV1{}
	err := common.JsonFileToSTH(sth, "./testdata/OldSTH.json")
	require.NoError(t, err, "Json File To STH Error")

	newSTH := &types.LogRootV1{}
	err = common.JsonFileToSTH(newSTH, "./testdata/NewSTH.json")
	require.NoError(t, err, "Json File To STH Error")

	logverifier := NewLogVerifier(nil)

	consistencyProof := [][]byte{{64, 106, 6, 19, 34, 220, 83, 247, 215, 32, 162, 107, 246, 239, 177, 77, 169, 60, 41, 70, 230, 0, 241, 108,
		241, 160, 11, 86, 200, 221, 122, 120}}

	_, err = logverifier.VerifyRoot(sth, newSTH, consistencyProof)
	require.NoError(t, err, "Verify Root Error")
}

func TestCheckRPC(t *testing.T) {
	rpc := &common.RPC{}

	err := common.JsonFileToRPC(rpc, "./testdata/rpc.json")
	require.NoError(t, err, "Json File To RPC Error")

	logverifier := NewLogVerifier(nil)

	err = logverifier.VerifyRPC(rpc)
	require.NoError(t, err)
}

func TestCheckSP(t *testing.T) {
	sp := &common.SP{}

	err := common.JsonFileToSP(sp, "./testdata/sp.json")
	require.NoError(t, err, "Json File To RPC Error")

	logverifier := NewLogVerifier(nil)

	err = logverifier.VerifySP(sp)
	require.NoError(t, err)
}
