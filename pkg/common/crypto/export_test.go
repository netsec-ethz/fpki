package crypto

import (
	"crypto/rsa"
)

func SignStructRSASHA256(s any, key *rsa.PrivateKey) ([]byte, error) {
	return signStructRSASHA256(s, key)
}
