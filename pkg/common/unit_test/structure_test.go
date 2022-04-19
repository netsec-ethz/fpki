package main

import (
	common "common.FPKI.github.com"
	"crypto/rand"
	"testing"
	"time"
)

//------------------------------------------------------
//           tests for structure.go
//------------------------------------------------------

// Equal funcs for every structure
func Test_Equal(t *testing.T) {

	rcsr := &common.RCSR{
		Subject:            "bandqhvdbdlwnd",
		Version:            6789,
		TimeStamp:          time.Now(),
		PublicKeyAlgorithm: common.RSA,
		PublicKey:          generateRandomBytes(),
		SignatureAlgorithm: common.SHA256,
		PRCSignature:       generateRandomBytes(),
		Signature:          generateRandomBytes(),
	}

	if !rcsr.Equal(rcsr) {
		t.Errorf("RCSR Equal() error")
		return
	}

	spt1 := &common.SPT{
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

	spt2 := &common.SPT{
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

	if !spt1.Equal(spt1) || !spt2.Equal(spt2) || spt1.Equal(spt2) || spt2.Equal(spt1) {
		t.Errorf("SPT Equal() error")
		return
	}

	sprt := &common.SPRT{
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
	if !sprt.Equal(sprt) {
		t.Errorf("SPRT Equal() error")
		return
	}

	rpc := &common.RPC{
		SerialNumber:       1729381,
		Subject:            "bad domain",
		Version:            1729381,
		PublicKeyAlgorithm: common.RSA,
		PublicKey:          generateRandomBytes(),
		NotBefore:          time.Now(),
		NotAfter:           time.Now(),
		CAName:             "bad domain",
		SignatureAlgorithm: common.SHA256,
		TimeStamp:          time.Now(),
		PRCSignature:       generateRandomBytes(),
		CASignature:        generateRandomBytes(),
		SPTs:               []common.SPT{*spt1, *spt2},
	}

	if !rpc.Equal(rpc) {
		t.Errorf("RPC Equal() error")
		return
	}
}

// RPC -> file -> RPC
func Test_Json_Read_Write(t *testing.T) {
	spt1 := &common.SPT{
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

	spt2 := &common.SPT{
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

	rpc := &common.RPC{
		SerialNumber:       1729381,
		Subject:            "bad domain",
		Version:            1729381,
		PublicKeyAlgorithm: common.RSA,
		PublicKey:          generateRandomBytes(),
		NotBefore:          time.Now(),
		NotAfter:           time.Now(),
		CAName:             "bad domain",
		SignatureAlgorithm: common.SHA256,
		TimeStamp:          time.Now(),
		PRCSignature:       generateRandomBytes(),
		CASignature:        generateRandomBytes(),
		SPTs:               []common.SPT{*spt1, *spt2},
	}

	err := common.Json_StrucToFile(rpc, "rpc_test")
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	rpc1 := &common.RPC{}
	err = common.Json_FileToRPC(rpc1, "rpc_test")
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	if !rpc.Equal(rpc1) {
		t.Errorf("Json error")
		return
	}
}

//-------------------------------------------------------------
//                    funcs for testing
//-------------------------------------------------------------
func generateRandomBytes() []byte {
	token := make([]byte, 40)
	rand.Read(token)
	return token
}

func generateRandomBytesArray() [][]byte {
	return [][]byte{generateRandomBytes()}
}
