package common

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
)

// ----------------------------------------------------------------------------------
//                     Key or certificate related functions
// ----------------------------------------------------------------------------------

// RsaPublicKeyToPemBytes() marshall public key to bytes
func RsaPublicKeyToPemBytes(pubkey *rsa.PublicKey) ([]byte, error) {
	pubkey_bytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return []byte{}, fmt.Errorf("RsaPublicKeyToPemBytes | MarshalPKIXPublicKey | %s", err.Error())
	}
	pubkey_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubkey_bytes,
		},
	)

	return pubkey_pem, nil
}

// PemBytesToRsaPublicKey() unmarshall bytes to public key
func PemBytesToRsaPublicKey(pubkey []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pubkey)
	if block == nil {
		return nil, fmt.Errorf("PemBytesToRsaPublicKey | Decode | block empty")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("PemBytesToRsaPublicKey | ParsePKIXPublicKey | %s", err.Error())
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		break
	}
	return nil, errors.New("PemBytesToRsaPublicKey | ParsePKIXPublicKey | Key type is not RSA")
}

// read x509 cert from files
func X509CertFromFile(fileName string) (*x509.Certificate, error) {
	content, err := ioutil.ReadFile(fileName)

	if err != nil {
		return nil, fmt.Errorf("X509CertFromFile | failed to read %s: %s", fileName, err)
	}

	var block *pem.Block
	block, _ = pem.Decode(content)

	if block == nil {
		return nil, fmt.Errorf("X509CertFromFile | no pem block in %s", fileName)
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("X509CertFromFile | %s contains data other than certificate", fileName)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("X509CertFromFile | ParseCertificate | %s", err.Error())
	}

	return cert, nil
}

// load rsa key pair from file
func LoadRSAKeyPairFromFile(keyPath string) (*rsa.PrivateKey, error) {
	bytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("LoadPrivPubKeyFromFile | read file | %s", err.Error())
	}

	block, _ := pem.Decode(bytes)

	keyPair, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("LoadPrivPubKeyFromFile | ParsePKCS1PrivateKey |%s", err.Error())
	}
	return keyPair, nil
}
