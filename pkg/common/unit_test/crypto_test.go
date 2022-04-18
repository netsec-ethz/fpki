package main

import (
	common "common.FPKI.github.com"
	"crypto/rand"
	"testing"
	"time"
)

//------------------------------------------------------
//           tests for crypto.go
//------------------------------------------------------

func Test_Signature_Of_RCSR(t *testing.T) {
	privKey, err := common.LoadRSAKeyPairFromFile("/Users/yongzhe/Desktop/fpki/pkg/common/unit_test/unit_test_cert/client_key.pem")
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	test := &common.RCSR{
		Subject:            "this is a test",
		Version:            44,
		TimeStamp:          time.Now(),
		PublicKeyAlgorithm: common.RSA,
		SignatureAlgorithm: common.SHA256,
		PRCSignature:       generateRandomBytes(),
		Signature:          generateRandomBytes(),
	}

	pubKeyBytes, err := common.RsaPublicKeyToPemBytes(&privKey.PublicKey)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	test.PublicKey = pubKeyBytes

	err = common.RCSR_CreateSignature(privKey, test)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	err = common.RCSR_VerifySignature(test)
	if err != nil {
		t.Errorf(err.Error())
		return
	}
}

// only check if the CA signature is correct
func Test_Issuance_Of_RPC(t *testing.T) {
	// -------------------------------------
	//  phase 1: domain owner generate rcsr
	// -------------------------------------
	privKey, err := common.LoadRSAKeyPairFromFile("./unit_test_cert/client_key.pem")
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	rcsr := &common.RCSR{
		Subject:            "this is a test",
		Version:            44,
		TimeStamp:          time.Now(),
		PublicKeyAlgorithm: common.RSA,
		SignatureAlgorithm: common.SHA256,
		PRCSignature:       generateRandomBytes(),
		Signature:          generateRandomBytes(),
	}

	// add public key
	pubKeyBytes, err := common.RsaPublicKeyToPemBytes(&privKey.PublicKey)
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	rcsr.PublicKey = pubKeyBytes

	// generate signature for rcsr
	err = common.RCSR_CreateSignature(privKey, rcsr)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	// -------------------------------------
	//  phase 2: pca issue rpc
	// -------------------------------------
	// validate the signature in rcsr
	err = common.RCSR_VerifySignature(rcsr)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	pcaPrivKey, err := common.LoadRSAKeyPairFromFile("./unit_test_cert/server_key.pem")
	rpc, err := common.RCSR_GenerateRPC(rcsr, time.Now(), 1, pcaPrivKey, "fpki")
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	if len(rpc.SPTs) != 0 {
		t.Errorf("Has SPTs")
		return
	}

	// -------------------------------------
	//  phase 3: domain owner check rpc
	// -------------------------------------

	caCert, err := common.X509CertFromFile("./unit_test_cert/server_cert.pem")
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	err = common.RPC_VerifyCASignature(caCert, rpc)

	if err != nil {
		t.Errorf(err.Error())
		return
	}
}

func generateRandomBytes() []byte {
	token := make([]byte, 40)
	rand.Read(token)
	return token
}

func generateRandomBytesArray() [][]byte {
	return [][]byte{generateRandomBytes()}
}
