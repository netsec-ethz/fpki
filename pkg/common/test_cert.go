package common

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

//------------------------------------------------------
//           tests for cert.go
//------------------------------------------------------

// TODO: more unit tests

// public key -> bytes -> public key
func Test_Enc_And_Dec_Of_PubKey(t *testing.T) {
	privateKeyPair, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Errorf("Keypair generation error")
		return
	}

	bytes, err := RsaPublicKeyToPemBytes(&privateKeyPair.PublicKey)
	if err != nil {
		t.Errorf("Encoding error")
		return
	}

	pubKey, err := PemBytesToRsaPublicKey(bytes)
	if err != nil {
		t.Errorf("Decoding error")
		return
	}

	if !privateKeyPair.PublicKey.Equal(pubKey) {
		t.Errorf("Parsing error")
		return
	}
}
