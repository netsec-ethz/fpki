package common

import (
	"crypto/rand"
	"testing"
	"time"
)

//------------------------------------------------------
//           tests for crypto.go
//------------------------------------------------------

// Generate RCSR -> generate signature for RCSR -> verify signature
func Test_Signature_Of_RCSR(t *testing.T) {
	privKey, err := LoadRSAKeyPairFromFile("./testdata/client_key.pem")
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	test := &RCSR{
		Subject:            "this is a test",
		Version:            44,
		TimeStamp:          time.Now(),
		PublicKeyAlgorithm: RSA,
		SignatureAlgorithm: SHA256,
		PRCSignature:       generateRandomBytes(),
		Signature:          generateRandomBytes(),
	}

	pubKeyBytes, err := RsaPublicKeyToPemBytes(&privKey.PublicKey)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	test.PublicKey = pubKeyBytes

	err = RCSRCreateSignature(privKey, test)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	err = RCSRVerifySignature(test)
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
	privKey, err := LoadRSAKeyPairFromFile("./testdata/client_key.pem")
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	rcsr := &RCSR{
		Subject:            "this is a test",
		Version:            44,
		TimeStamp:          time.Now(),
		PublicKeyAlgorithm: RSA,
		SignatureAlgorithm: SHA256,
		PRCSignature:       generateRandomBytes(),
		Signature:          generateRandomBytes(),
	}

	// add public key
	pubKeyBytes, err := RsaPublicKeyToPemBytes(&privKey.PublicKey)
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	rcsr.PublicKey = pubKeyBytes

	// generate signature for rcsr
	err = RCSRCreateSignature(privKey, rcsr)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	// -------------------------------------
	//  phase 2: pca issue rpc
	// -------------------------------------
	// validate the signature in rcsr
	err = RCSRVerifySignature(rcsr)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	pcaPrivKey, err := LoadRSAKeyPairFromFile("./testdata/server_key.pem")
	rpc, err := RCSRGenerateRPC(rcsr, time.Now(), 1, pcaPrivKey, "fpki")
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

	caCert, err := X509CertFromFile("./testdata/server_cert.pem")
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	err = RPCVerifyCASignature(caCert, rpc)

	if err != nil {
		t.Errorf(err.Error())
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