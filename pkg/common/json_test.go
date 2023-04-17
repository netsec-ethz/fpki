package common

import (
	"os"
	"path"
	"reflect"
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

func TestToFromJSON(t *testing.T) {
	cases := map[string]struct {
		data any
	}{
		"trillian.Proof": {
			data: &trillian.Proof{
				LeafIndex: 1,
				Hashes:    generateRandomBytesArray(),
			},
		},
		"slice_of_trillian.Proof": {
			data: []*trillian.Proof{
				{
					LeafIndex: 1,
					Hashes:    generateRandomBytesArray(),
				},
				{
					LeafIndex: 2,
					Hashes:    generateRandomBytesArray(),
				},
				{
					LeafIndex: 3,
					Hashes:    generateRandomBytesArray(),
				},
			},
		},
		"trilliantypes.LogRootV1": {
			data: &trilliantypes.LogRootV1{
				TreeSize:       1,
				RootHash:       generateRandomBytes(),
				TimestampNanos: 11,
				Revision:       3,
				Metadata:       generateRandomBytes(),
			},
		},
	}

	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			expectedType := reflect.TypeOf(tc.data) // type will be a pointer to RPC, etc.
			d, err := ToJSON(tc.data)
			t.Logf("JSON: %s", string(d))
			require.NoError(t, err)

			o, err := FromJSON(d)
			require.NoError(t, err)
			require.NotNil(t, o)
			require.Equal(t, tc.data, o)

			gotType := reflect.TypeOf(o)
			require.Equal(t, expectedType, gotType)
		})
	}
}
