package util

import (
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"

	ctx509 "github.com/google/certificate-transparency-go/x509"
)

func RSAPublicToPEM(pubkey *rsa.PublicKey) ([]byte, error) {
	pubkey_bytes, err := ctx509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubkey_bytes,
		},
	), nil
}

func PEMToRSAPublic(pubkey []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pubkey)
	if block == nil {
		return nil, fmt.Errorf("PemBytesToRsaPublicKey | Decode | block empty")
	}

	pub, err := ctx509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("PemBytesToRsaPublicKey | ParsePKIXPublicKey | %w", err)
	}

	pubKeyResult, ok := pub.(*rsa.PublicKey)
	if ok {
		return pubKeyResult, nil
	}
	return nil, errors.New("PemBytesToRsaPublicKey | ParsePKIXPublicKey | Key type is not RSA")
}
