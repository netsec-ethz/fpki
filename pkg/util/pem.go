package util

import (
	"crypto/rsa"
	"fmt"

	ctx509 "github.com/google/certificate-transparency-go/x509"
)

func RSAPublicToDERBytes(pubKey *rsa.PublicKey) ([]byte, error) {
	return ctx509.MarshalPKIXPublicKey(pubKey)
}

func DERBytesToRSAPublic(derBytes []byte) (*rsa.PublicKey, error) {
	rawKey, err := ctx509.ParsePKIXPublicKey(derBytes)
	if err != nil {
		return nil, err
	}
	key, ok := rawKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not RSA, but %T", rawKey)
	}
	return key, nil
}
