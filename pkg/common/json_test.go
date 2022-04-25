package common

import (
	"testing"
	"time"
)

//------------------------------------------------------
//           tests for json.go
//------------------------------------------------------

// SPT -> bytes -> SPT
func Test_Encode_And_Decode_Of_SPT(t *testing.T) {

	test := &SPT{
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

	result, err := JsonStrucToBytes(test)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	deserlialisedSPT, err := JsonBytesToSPT(result)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	if !deserlialisedSPT.Equal(test) {
		t.Errorf("SPT serialise and deserialise error.")
	}
}

// RPC -> bytes -> RPC
func Test_Encode_And_Decode_Of_RPC(t *testing.T) {
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

	test := &RPC{
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

	result, err := JsonStrucToBytes(test)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	deserlialisedRPC, err := JsonBytesToRPC(result)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	if !deserlialisedRPC.Equal(test) {
		t.Errorf("RPC serialise and deserialise error.")
	}
}
