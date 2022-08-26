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

	err := JsonStrucToFile(spt, tempFile)
	require.NoError(t, err, "Json Struc To File error")

	deserialisedSPT := &SPT{}

	err = JsonFileToSPT(deserialisedSPT, tempFile)
	require.NoError(t, err, "Json File To SPT error")

	assert.True(t, deserialisedSPT.Equal(*spt), "SPT serialised and deserialised error")
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

	err := JsonStrucToFile(rpc, tempFile)
	require.NoError(t, err, "Json Struc To File error")

	deserialisedSPT := &RPC{}

	err = JsonFileToRPC(deserialisedSPT, tempFile)
	require.NoError(t, err, "Json File To RPC error")

	assert.True(t, deserialisedSPT.Equal(rpc), "RPC serialised and deserialised error")
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

	err := JsonStrucToFile(&pc, tempFile)
	require.NoError(t, err, "Json Struc To File error")

	deserialisedPC := &SP{}

	err = JsonFileToSP(deserialisedPC, tempFile)
	require.NoError(t, err, "Json File To SPT error")

	assert.True(t, deserialisedPC.Equal(pc), "PC serialised and deserialised error")
}
