package common

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// // RsaPublicKeyToPemBytes: marshall public key to bytes
// func RsaPublicKeyToPemBytes(pubkey *rsa.PublicKey) ([]byte, error) {
// 	pubkey_bytes, err := x509.MarshalPKIXPublicKey(pubkey)
// 	if err != nil {
// 		return nil, fmt.Errorf("RsaPublicKeyToPemBytes | MarshalPKIXPublicKey | %w", err)
// 	}

// 	return pem.EncodeToMemory(
// 		&pem.Block{
// 			Type:  "RSA PUBLIC KEY",
// 			Bytes: pubkey_bytes,
// 		},
// 	), nil
// }

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
