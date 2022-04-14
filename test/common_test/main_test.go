package main

import (
	"bytes"
	common "common.FPKI.github.com"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"
)

//------------------------------------------------------
//           tests for structure.go
//------------------------------------------------------
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
		PoI:             generateRandomBytes(),
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
		PoI:             generateRandomBytes(),
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
		PoI:             generateRandomBytes(),
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

//------------------------------------------------------
//           tests for crypto.go
//------------------------------------------------------

func Test_Enc_And_Dec_Of_PubKey(t *testing.T) {
	privateKeyPair, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Errorf("Keypair generation error")
		return
	}

	bytes, err := common.RsaPublicKeyToPemBytes(&privateKeyPair.PublicKey)
	if err != nil {
		t.Errorf("Encoding error")
		return
	}

	pubKey, err := common.PemBytesToRsaPublicKey(bytes)
	if err != nil {
		t.Errorf("Decoding error")
		return
	}

	if !privateKeyPair.PublicKey.Equal(pubKey) {
		t.Errorf("Parsing error")
		return
	}
}

func Test_Encode_And_Decode_Of_RCSR(t *testing.T) {
	test := &common.RCSR{
		Subject:            "this is a test",
		Version:            44,
		TimeStamp:          time.Now(),
		PublicKeyAlgorithm: common.RSA,
		PublicKey:          generateRandomBytes(),
		SignatureAlgorithm: common.SHA256,
		PRCSignature:       generateRandomBytes(),
		Signature:          generateRandomBytes(),
	}

	result, err := common.SerialiseStruc(test)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	deserlialisedRCSR, err := common.DeserialiseRCSR(result)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	if deserlialisedRCSR.Subject != test.Subject ||
		deserlialisedRCSR.Version != test.Version ||
		!deserlialisedRCSR.TimeStamp.Equal(test.TimeStamp) ||
		deserlialisedRCSR.PublicKeyAlgorithm != test.PublicKeyAlgorithm ||
		bytes.Compare(deserlialisedRCSR.PublicKey, test.PublicKey) != 0 ||
		deserlialisedRCSR.SignatureAlgorithm != test.SignatureAlgorithm ||
		bytes.Compare(deserlialisedRCSR.PRCSignature, test.PRCSignature) != 0 ||
		bytes.Compare(deserlialisedRCSR.Signature, test.Signature) != 0 {

		t.Errorf("RCSR serialise and deserialise error.")
	}
}

func Test_Encrption_and_Decryption_Of_RCSR(t *testing.T) {
	privKey, err := common.LoadRSAKeyPairFromFile("/Users/yongzhe/Desktop/FPKI/cert/PCACert/server_key.pem")
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

	err = common.SignRCSR(privKey, test)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	err = common.VerifyRCSR(test)
	if err != nil {
		t.Errorf(err.Error())
		return
	}
}

func Test_Signing_and_Verifying_Of_RPC(t *testing.T) {
	privKey, err := common.LoadRSAKeyPairFromFile("/Users/yongzhe/Desktop/FPKI/cert/PCACert/server_key.pem")
	test := &common.RCSR{
		Subject:            "this is a test",
		Version:            44,
		TimeStamp:          time.Now(),
		PublicKeyAlgorithm: common.RSA,
		PublicKey:          generateRandomBytes(),
		SignatureAlgorithm: common.SHA256,
		PRCSignature:       generateRandomBytes(),
		Signature:          generateRandomBytes(),
	}

	err = common.SignRCSR(privKey, test)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	rpc, err := common.RCSRToRPC(test, time.Now(), 1, privKey, "fpki")
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	if len(rpc.SPTs) != 0 {
		t.Errorf("Has SPTs")
		return
	}

	caCert, err := common.X509CertFromFile("/Users/yongzhe/Desktop/FPKI/cert/PCACert/server_cert.pem")
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	err = common.VerifyRPC(caCert, rpc)

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
