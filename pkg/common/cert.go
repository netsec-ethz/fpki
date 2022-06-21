package common

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"

	ctX509 "github.com/google/certificate-transparency-go/x509"
)

// RsaPublicKeyToPemBytes: marshall public key to bytes
func RsaPublicKeyToPemBytes(pubkey *rsa.PublicKey) ([]byte, error) {
	pubkey_bytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return nil, fmt.Errorf("RsaPublicKeyToPemBytes | MarshalPKIXPublicKey | %w", err)
	}

	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubkey_bytes,
		},
	), nil
}

// PemBytesToRsaPublicKey: unmarshal bytes to public key
func PemBytesToRsaPublicKey(pubkey []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pubkey)
	if block == nil {
		return nil, fmt.Errorf("PemBytesToRsaPublicKey | Decode | block empty")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("PemBytesToRsaPublicKey | ParsePKIXPublicKey | %w", err)
	}

	pubKeyResult, ok := pub.(*rsa.PublicKey)
	if ok {
		return pubKeyResult, nil
	}
	return nil, errors.New("PemBytesToRsaPublicKey | ParsePKIXPublicKey | Key type is not RSA")
}

// X509CertFromFile: read x509 cert from files
func X509CertFromFile(fileName string) (*x509.Certificate, error) {
	content, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("X509CertFromFile | failed to read %s: %w", fileName, err)
	}

	var block *pem.Block
	block, _ = pem.Decode(content)

	switch {
	case block == nil:
		return nil, fmt.Errorf("X509CertFromFile | no pem block in %s", fileName)
	case block.Type != "CERTIFICATE":
		return nil, fmt.Errorf("X509CertFromFile | %s contains data other than certificate", fileName)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("X509CertFromFile | ParseCertificate | %w", err)
	}

	return cert, nil
}

// LoadRSAKeyPairFromFile: load rsa key pair from file
func LoadRSAKeyPairFromFile(keyPath string) (*rsa.PrivateKey, error) {
	bytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("LoadRSAKeyPairFromFile | read file | %w", err)
	}

	block, _ := pem.Decode(bytes)

	keyPair, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("LoadRSAKeyPairFromFile | ParsePKCS1PrivateKey | %w", err)
	}
	return keyPair, nil
}

// X509CertFromFile: read x509 cert from files
func CTX509CertFromFile(fileName string) (*ctX509.Certificate, error) {
	content, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("X509CertFromFile | failed to read %s: %w", fileName, err)
	}

	var block *pem.Block
	block, _ = pem.Decode(content)

	switch {
	case block == nil:
		return nil, fmt.Errorf("X509CertFromFile | no pem block in %s", fileName)
	case block.Type != "CERTIFICATE":
		return nil, fmt.Errorf("X509CertFromFile | %s contains data other than certificate", fileName)
	}

	cert, err := ctX509.ParseCertificate(block.Bytes)
	if err != nil {
		cert, err = ctX509.ParseTBSCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("X509CertFromFile | ParseTBSCertificate | %w", err)
		}
	}

	return cert, nil
}
