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
//           tests for structure.go
//------------------------------------------------------

// TestEqual: Equal funcs for every structure
func TestEqual(t *testing.T) {
	rcsr := &RCSR{
		Subject:            "bandqhvdbdlwnd",
		Version:            6789,
		TimeStamp:          time.Now(),
		PublicKeyAlgorithm: RSA,
		PublicKey:          generateRandomBytes(),
		SignatureAlgorithm: SHA256,
		PRCSignature:       generateRandomBytes(),
		Signature:          generateRandomBytes(),
	}

	assert.True(t, rcsr.Equal(rcsr), "RCSR Equal() error")

	spt1 := SPT{
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

	spt2 := SPT{
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

	assert.True(t, spt1.Equal(spt1) && spt2.Equal(spt2) && !spt1.Equal(spt2) && !spt2.Equal(spt1), "SPT Equal() error")

	sprt := &SPRT{
		Version:         12314,
		Subject:         "bad domain",
		CAName:          "I'm malicious CA, nice to meet you",
		LogID:           1729381,
		CertType:        0x21,
		AddedTS:         time.Now(),
		STH:             generateRandomBytes(),
		PoI:             generateRandomBytesArray(),
		STHSerialNumber: 1729381,
		Reason:          1729381,
		Signature:       generateRandomBytes(),
	}

	assert.True(t, sprt.Equal(sprt), "SPRT Equal() error")

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
		SPTs:               []SPT{spt1, spt2},
	}

	assert.True(t, rpc.Equal(rpc), "RPC Equal() error")
}

// TestJsonReadWrite: RPC -> file -> RPC, then RPC.Equal(RPC)
func TestJsonReadWrite(t *testing.T) {
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

	tempFile := path.Join(os.TempDir(), "rpctest.json")
	defer os.Remove(tempFile)
	err := JsonStrucToFile(rpc, tempFile)
	require.NoError(t, err, "Json Struc To File error")

	rpc1 := &RPC{}
	err = JsonFileToRPC(rpc1, tempFile)
	require.NoError(t, err, "Json File To RPC error")

	assert.True(t, rpc.Equal(rpc1), "Json error")
}
