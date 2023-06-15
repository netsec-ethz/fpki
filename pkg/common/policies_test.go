package common_test

import (
	"os"
	"path"
	"testing"

	"github.com/google/trillian"
	trilliantypes "github.com/google/trillian/types"
	"github.com/stretchr/testify/require"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/netsec-ethz/fpki/pkg/tests/random"
)

var update = tests.UpdateGoldenFiles()

func TestGenerateGoldenFiles(t *testing.T) {
	// Update the JSON files in tests/testdata
	if *update {
		obj := []any{random.RandomSP(t), random.RandomSP(t)}
		err := common.ToJSONFile(obj, "../../tests/testdata/2-SPs.json")
		require.NoError(t, err)
	}
}

// TestEqual: Equal funcs for every structure
func TestEqual(t *testing.T) {
	rcsr := random.RandomRCSR(t)
	require.True(t, rcsr.Equal(rcsr))

	spt1 := *random.RandomSPT(t)
	spt2 := *random.RandomSPT(t)
	require.True(t, spt1.Equal(spt1))
	require.True(t, spt2.Equal(spt2))
	require.False(t, spt1.Equal(spt2))
	require.False(t, spt2.Equal(spt1))

	sprt := random.RandomSPRT(t)
	require.True(t, sprt.Equal(sprt))

	rpc := random.RandomRPC(t)
	require.True(t, rpc.Equal(rpc))
}

// TestJsonReadWrite: RPC -> file -> RPC, then RPC.Equal(RPC)
func TestJsonReadWrite(t *testing.T) {
	rpc := random.RandomRPC(t)
	rpc.SPTs = []common.SPT{
		*random.RandomSPT(t),
		*random.RandomSPT(t),
	}

	tempFile := path.Join(os.TempDir(), "rpctest.json")
	defer os.Remove(tempFile)
	err := common.ToJSONFile(rpc, tempFile)
	require.NoError(t, err, "Json Struct To File error")

	rpc1, err := common.JsonFileToRPC(tempFile)
	require.NoError(t, err, "Json File To RPC error")

	require.True(t, rpc.Equal(rpc1), "Json error")
}

func randomTrillianProof(t tests.T) *trillian.Proof {
	return &trillian.Proof{
		LeafIndex: 1,
		Hashes:    [][]byte{random.RandomBytesForTest(t, 32)},
	}
}

func randomLogRootV1(t tests.T) *trilliantypes.LogRootV1 {
	return &trilliantypes.LogRootV1{
		TreeSize:       1,
		RootHash:       random.RandomBytesForTest(t, 32),
		TimestampNanos: 11,
		Revision:       3,
		Metadata:       random.RandomBytesForTest(t, 40),
	}
}
