package common

import (
	"os"
	"path"
	"testing"
	"time"

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
		AddedTS:         time.Now(),
		STH:             generateRandomBytes(),
		PoI:             generateRandomBytesArray(),
		STHSerialNumber: 7689,
		Signature:       generateRandomBytes(),
	}

	err := JsonStructToFile(spt, tempFile)
	require.NoError(t, err, "Json Struct To File error")

	deserializedSPT := &SPT{}

	err = JsonFileToSPT(deserializedSPT, tempFile)
	require.NoError(t, err, "Json File To SPT error")

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
		PoI:             generateRandomBytesArray(),
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
		PoI:             generateRandomBytesArray(),
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

	err := JsonStructToFile(rpc, tempFile)
	require.NoError(t, err, "Json Struct To File error")

	deserializedSPT := &RPC{}

	err = JsonFileToRPC(deserializedSPT, tempFile)
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
		PoI:             generateRandomBytesArray(),
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

	err := JsonStructToFile(&pc, tempFile)
	require.NoError(t, err, "Json Struct To File error")

	deserializedPC := &SP{}

	err = JsonFileToSP(deserializedPC, tempFile)
	require.NoError(t, err, "Json File To SPT error")

	assert.True(t, deserializedPC.Equal(pc), "PC serialized and deserialized error")
}
