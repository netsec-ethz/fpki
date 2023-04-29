package common

import (
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	"github.com/google/trillian"
	trilliantypes "github.com/google/trillian/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//------------------------------------------------------
//           tests for json.go
//------------------------------------------------------

// TestEncodeAndDecodeOfSPT: SPT -> files -> SPT
func TestEncodeAndDecodeOfSPT(t *testing.T) {
	tempFile := path.Join("./", "spt.json")
	defer os.Remove(tempFile)

	spt := &SPT{
		Version:         12314,
		Subject:         "you are funny",
		CAName:          "hihihihihihi",
		LogID:           123412,
		CertType:        0x11,
		AddedTS:         nowWithoutMonotonic(),
		STH:             generateRandomBytes(),
		PoI:             generateRandomBytes(),
		STHSerialNumber: 7689,
		Signature:       generateRandomBytes(),
	}

	err := ToJSONFile(spt, tempFile)
	require.NoError(t, err, "Json Struct To File error")

	deserializedSPT, err := JsonFileToSPT(tempFile)
	require.NoError(t, err, "Json File To SPT error")

	assert.Equal(t, spt, deserializedSPT)
	assert.True(t, deserializedSPT.Equal(*spt), "SPT serialized and deserialized error")
}

// TestEncodeAndDecodeOfRPC: RPC -> files -> RPC
func TestEncodeAndDecodeOfRPC(t *testing.T) {
	tempFile := path.Join("./", "rpc.json")
	defer os.Remove(tempFile)

	spt1 := &SPT{
		Version:         12313,
		Subject:         "hihihihihhi",
		CAName:          "I'm honest CA, nice to meet you",
		LogID:           1231323,
		CertType:        0x11,
		AddedTS:         time.Now(),
		STH:             generateRandomBytes(),
		PoI:             generateRandomBytes(),
		STHSerialNumber: 131678,
		Signature:       generateRandomBytes(),
	}

	spt2 := &SPT{
		Version:         12368713,
		Subject:         "hohohoho",
		CAName:          "I'm malicious CA, nice to meet you",
		LogID:           1324123,
		CertType:        0x21,
		AddedTS:         time.Now(),
		STH:             generateRandomBytes(),
		PoI:             generateRandomBytes(),
		STHSerialNumber: 114378,
		Signature:       generateRandomBytes(),
	}

	rpc := &RPC{
		SerialNumber:       1729381,
		Subject:            "bad domain",
		Version:            1729381,
		PublicKeyAlgorithm: RSA,
		PublicKey:          generateRandomBytes(),
		NotBefore:          time.Now(),
		NotAfter:           time.Now(),
		CAName:             "bad domain",
		SignatureAlgorithm: SHA256,
		TimeStamp:          time.Now(),
		PRCSignature:       generateRandomBytes(),
		CASignature:        generateRandomBytes(),
		SPTs:               []SPT{*spt1, *spt2},
	}

	err := ToJSONFile(rpc, tempFile)
	require.NoError(t, err, "Json Struct To File error")

	deserializedSPT, err := JsonFileToRPC(tempFile)
	require.NoError(t, err, "Json File To RPC error")

	assert.True(t, deserializedSPT.Equal(rpc), "RPC serialized and deserialized error")
}

// TestEncodeAndDecodeOfPC: PC -> file -> PC
func TestEncodeAndDecodeOfPC(t *testing.T) {
	tempFile := path.Join("./", "pc.json")
	defer os.Remove(tempFile)

	spt := SPT{
		Version:         12368713,
		Subject:         "hohohoho",
		CAName:          "I'm malicious CA, nice to meet you",
		LogID:           1324123,
		CertType:        0x21,
		AddedTS:         time.Now(),
		STH:             generateRandomBytes(),
		PoI:             generateRandomBytes(),
		STHSerialNumber: 114378,
		Signature:       generateRandomBytes(),
	}

	policy := Policy{
		TrustedCA: []string{"my CA"},
	}

	pc := SP{
		Policies:          policy,
		TimeStamp:         time.Now(),
		Subject:           "hihihi",
		CAName:            "hihihi",
		SerialNumber:      1,
		CASignature:       []byte{1, 4, 2, 1, 4},
		RootCertSignature: []byte{1, 4, 2, 1, 4},
		SPTs:              []SPT{spt},
	}

	err := ToJSONFile(&pc, tempFile)
	require.NoError(t, err, "Json Struct To File error")

	deserializedPC, err := JsonFileToSP(tempFile)
	require.NoError(t, err, "Json File To SPT error")

	assert.True(t, deserializedPC.Equal(pc), "PC serialized and deserialized error")
}

// TestPolicyObjects checks that the structure types in the test cases can be converted to JSON and
// back, using the functions ToJSON and FromJSON.
// It checks after deserialization that the objects are equal.
func TestPolicyObjects(t *testing.T) {
	cases := []struct {
		data any
	}{
		{
			data: randomRPC(),
		},
		{
			data: *randomRPC(),
		},
		{
			data: randomRCSR(),
		},
		{
			data: randomSP(),
		},
		{
			data: []any{
				randomRPC(),
				randomRCSR(),
				randomSP(),
				randomSPRT(),
				randomPSR(),
				randomTrillianProof(),
				randomLogRootV1(),
			},
		},
		{
			data: []any{
				randomRPC(),
				[]any{
					randomSP(),
					randomSPT(),
				},
				[]any{
					randomTrillianProof(),
					randomTrillianProof(),
				},
			},
		},
	}
	for i, tc := range cases {
		i, tc := i, tc
		t.Run(fmt.Sprintf("case_%d", i), func(t *testing.T) {
			t.Parallel()
			// Serialize.
			data, err := ToJSON(tc.data)
			require.NoError(t, err)
			// Deserialize.
			deserialized, err := FromJSON(data)
			require.NoError(t, err)
			// Compare.
			require.Equal(t, tc.data, deserialized)
		})
	}
}

func randomTrillianProof() *trillian.Proof {
	return &trillian.Proof{
		LeafIndex: 1,
		Hashes:    generateRandomBytesArray(),
	}
}

func randomLogRootV1() *trilliantypes.LogRootV1 {
	return &trilliantypes.LogRootV1{
		TreeSize:       1,
		RootHash:       generateRandomBytes(),
		TimestampNanos: 11,
		Revision:       3,
		Metadata:       generateRandomBytes(),
	}
}
