package DomainOwner

import (
	common "common.FPKI.github.com"
	"crypto/rand"
	"crypto/rsa"
	"time"
)

type DomainOwner struct {
	// private & public key of the RPC
	currentPrivateKeyPair  *rsa.PrivateKey
	previousPrivateKeyPair *rsa.PrivateKey
}

func (do *DomainOwner) GenerateRCSR(subject string, version int) (common.RCSR, error) {
	err := do.GenerateRSAPrivKey()

	rcsr := common.RCSR{}
	if err != nil {
		return rcsr, err
	}

	rcsr.Subject = subject
	rcsr.Version = version
	rcsr.TimeStamp = time.Now()
	rcsr.PublicKeyAlgorithm = common.RSA
	pubKeyBytes, err := common.RsaPublicKeyToPemBytes(&do.currentPrivateKeyPair.PublicKey)
	if err != nil {
		return rcsr, err
	}

	rcsr.PublicKey = pubKeyBytes
	rcsr.SignatureAlgorithm = common.SHA256

	if do.previousPrivateKeyPair != nil {
		err = common.GeneratePRCSignatureForRCSR(&rcsr, do.previousPrivateKeyPair)
		if err != nil {
			return common.RCSR{}, err
		}
	}

	err = common.SignRCSR(do.currentPrivateKeyPair, &rcsr)

	if err != nil {
		return common.RCSR{}, err
	}

	return rcsr, nil
}

// generate new rsa key pair
func (do *DomainOwner) GenerateRSAPrivKey() error {
	privateKeyPair, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		return err
	} else {
		do.previousPrivateKeyPair = do.currentPrivateKeyPair
		do.currentPrivateKeyPair = privateKeyPair
		return nil
	}
}
