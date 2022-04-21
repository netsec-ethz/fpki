package domainowner

import (
	"crypto/rand"
	"crypto/rsa"
	common "github.com/netsec-ethz/fpki/pkg/common"
	"time"
)

// Assume one domain owner only have one domain; Logic can be changed later
// Cool-off period is not fully implemented.

// Public func for user
// NewDomainOwner:     create a new domain owner
// GenerateRCSR:       generate a new Root Certificate Signing Request

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
	// generate a fresh RSA key pair; new RSA key for every RCSR, thus every RPC
	err := do.generateRSAPrivKey()
	if err != nil {
		return &common.RCSR{}, err
	}

	// generate rcsr
	rcsr := &common.RCSR{}

	// if domain name not specified, use the default one
	if domainName == "" {
		rcsr.Subject = do.domainName
	}
	rcsr.Version = version
	rcsr.TimeStamp = time.Now()
	rcsr.PublicKeyAlgorithm = common.RSA

	// marshall public key into bytes
	pubKeyBytes, err := common.RsaPublicKeyToPemBytes(&do.currentPrivateKeyPair.PublicKey)
	if err != nil {
		return rcsr, err
	}

	rcsr.PublicKey = pubKeyBytes
	rcsr.SignatureAlgorithm = common.SHA256

	// if domain owner still have the private key of the previous RPC -> can avoid cool-off period
	if do.previousPrivateKeyPair != nil {
		err = common.RCSR_GenerateRPCSignature(rcsr, do.previousPrivateKeyPair)
		if err != nil {
			return &common.RCSR{}, err
		}
	}

	// generate signature for RCSR, using the new pub key
	err = common.RCSR_CreateSignature(do.currentPrivateKeyPair, rcsr)

	if err != nil {
		return &common.RCSR{}, err
	}

	return rcsr, nil
}

// generate new rsa key pair
func (do *DomainOwner) generateRSAPrivKey() error {
	privateKeyPair, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		return err
	} else {
		do.previousPrivateKeyPair = do.currentPrivateKeyPair
		do.currentPrivateKeyPair = privateKeyPair
		return nil
	}
}
