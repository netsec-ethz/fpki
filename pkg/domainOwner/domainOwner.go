package domainOwner

import (
	common "common.FPKI.github.com"
	"crypto/rand"
	"crypto/rsa"
	"time"
)

// Assume one domain owner only have one domain; Logic can be changed later
// Cool-off period is not fully implemented.

type DomainOwner struct {
	// private & public key of the RPC
	currentPrivateKeyPair  *rsa.PrivateKey
	previousPrivateKeyPair *rsa.PrivateKey
	domainName             string
}

func NewDomainOwner(subject string) *DomainOwner {
	return &DomainOwner{domainName: subject}
}

// subject is the name of the domain: eg. fpki.com
func (do *DomainOwner) GenerateRCSR(domainName string, version int) (*common.RCSR, error) {
	// generate a fresh RSA key pair
	err := do.GenerateRSAPrivKey()
	if err != nil {
		return &common.RCSR{}, err
	}

	// generate rcsr
	rcsr := &common.RCSR{}
	if domainName == "" {
		rcsr.Subject = do.domainName
	}
	rcsr.Version = version
	rcsr.TimeStamp = time.Now()
	rcsr.PublicKeyAlgorithm = common.RSA

	pubKeyBytes, err := common.RsaPublicKeyToPemBytes(&do.currentPrivateKeyPair.PublicKey)
	if err != nil {
		return rcsr, err
	}

	rcsr.PublicKey = pubKeyBytes
	rcsr.SignatureAlgorithm = common.SHA256

	// if domain owner still have the private key of the previous RPC -> to avoid cool-off period
	if do.previousPrivateKeyPair != nil {
		err = common.RCSR_GenerateRPCSignature(rcsr, do.previousPrivateKeyPair)
		if err != nil {
			return &common.RCSR{}, err
		}
	}

	err = common.RCSR_CreateSignature(do.currentPrivateKeyPair, rcsr)

	if err != nil {
		return &common.RCSR{}, err
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
