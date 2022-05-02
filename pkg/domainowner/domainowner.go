package domainowner

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
)

// Assume one domain owner only have one domain; Logic can be changed later
// Cool-off period is not fully implemented.

//DomainOwner: struc which represents one domain owner.
type DomainOwner struct {
	// private & public key of the RPC
	currentPrivateKeyPair  *rsa.PrivateKey
	previousPrivateKeyPair *rsa.PrivateKey
	domainName             string
}

// NewDomainOwner: returns a new domain owner
func NewDomainOwner(subject string) *DomainOwner {
	return &DomainOwner{domainName: subject}
}

// GenerateRCSR: Generate a Root Certificate Signing Request for one domain
// subject is the name of the domain: eg. fpki.com
func (do *DomainOwner) GenerateRCSR(domainName string, version int) (*common.RCSR, error) {
	// generate a fresh RSA key pair; new RSA key for every RCSR, thus every RPC
	err := do.generateRSAPrivKey()
	if err != nil {
		return nil, fmt.Errorf("GenerateRCSR | generateRSAPrivKey | %w", err)
	}

	// marshall public key into bytes
	pubKeyBytes, err := common.RsaPublicKeyToPemBytes(&do.currentPrivateKeyPair.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("GenerateRCSR | RsaPublicKeyToPemBytes | %w", err)
	}
	// generate rcsr
	rcsr := &common.RCSR{
		Version:            version,
		TimeStamp:          time.Now(),
		PublicKeyAlgorithm: common.RSA,
		PublicKey:          pubKeyBytes,
		SignatureAlgorithm: common.SHA256,
	}
	// if domain name not specified, use the default one
	if domainName == "" {
		rcsr.Subject = do.domainName
	}

	// if domain owner still have the private key of the previous RPC -> can avoid cool-off period
	if do.previousPrivateKeyPair != nil {
		err = common.RCSRGenerateRPCSignature(rcsr, do.previousPrivateKeyPair)
		if err != nil {
			return nil, fmt.Errorf("GenerateRCSR | RCSRGenerateRPCSignature | %w", err)
		}
	}

	// generate signature for RCSR, using the new pub key
	err = common.RCSRCreateSignature(do.currentPrivateKeyPair, rcsr)

	if err != nil {
		return nil, fmt.Errorf("GenerateRCSR | RCSRCreateSignature | %w", err)
	}

	return rcsr, nil
}

// generate new rsa key pair
func (do *DomainOwner) generateRSAPrivKey() error {
	privateKeyPair, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generateRSAPrivKey | GenerateKey | %w", err)
	}

	do.previousPrivateKeyPair = do.currentPrivateKeyPair
	do.currentPrivateKeyPair = privateKeyPair
	return nil
}
