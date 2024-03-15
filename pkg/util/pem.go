package util

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"

	ctx509 "github.com/google/certificate-transparency-go/x509"
)

func RSAPublicToDERBase64(pubKey *rsa.PublicKey) (string, error) {
	derBytes, err := RSAPublicToDERBytes(pubKey)
	if err != nil {
		return "", fmt.Errorf("Failed to convert public key to DER format: %s", err)
	}
	return base64.StdEncoding.EncodeToString(derBytes), nil
}

func DERBase64ToRSAPublic(base64PubKey string) (*rsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(base64PubKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode base64 public key: %s", err)
	}
	return DERBytesToRSAPublic(der)
}

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
