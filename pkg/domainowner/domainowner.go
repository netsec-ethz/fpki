package domainowner

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/common/crypto"
	"github.com/netsec-ethz/fpki/pkg/util"
)

// Assume one domain owner only have one domain; Logic can be changed later
// TODO(yongzhe): Cool-off period is not fully implemented.

// DomainOwner: struct which represents one domain owner.
type DomainOwner struct {
	privKeyByDomainName map[string]*rsa.PrivateKey
}

// NewDomainOwner: returns a new domain owner
func NewDomainOwner() *DomainOwner {
	return &DomainOwner{
		privKeyByDomainName: make(map[string]*rsa.PrivateKey),
	}
}

// GeneratePolCertSignRequest: Generate a Root Certificate Signing Request for one domain
// subject is the name of the domain: eg. fpki.com
func (do *DomainOwner) GeneratePolCertSignRequest(issuer, domainName string, version int) (*common.PolicyCertificateSigningRequest, error) {
	// Generate a fresh RSA key pair; new RSA key for every RCSR, thus every RPC
	newPrivKeyPair, err := do.generateRSAPrivKeyPair()
	if err != nil {
		return nil, fmt.Errorf("GeneratePolCertSignRequest | generateRSAPrivKey | %w", err)
	}
	// marshall public key into bytes
	pubKeyBytes, err := util.RSAPublicToDERBytes(&newPrivKeyPair.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("GeneratePolCertSignRequest | RsaPublicKeyToPemBytes | %w", err)
	}

	req := common.NewPolicyCertificateSigningRequest(
		version,
		issuer, // issuer
		domainName,
		0,          // serial number
		domainName, // domain
		time.Now(),
		time.Now().Add(time.Microsecond), // not after
		false,                            // is issuer
		pubKeyBytes,
		common.RSA,
		common.SHA256,
		time.Now(),                // timestamp
		common.PolicyAttributes{}, // policy attributes
		nil,                       // owner signature
		nil,                       // owner pub key hash
	)

	// if domain owner still have the private key of the previous RPC -> can avoid cool-off period
	if prevKey, ok := do.privKeyByDomainName[domainName]; ok {
		err = crypto.SignAsOwner(prevKey, req)
		if err != nil {
			return nil, fmt.Errorf("GeneratePolCertSignRequest | RCSRGenerateRPCSignature | %w", err)
		}
	}

	// Store the new keys for this domain as the latest owner keys.
	do.privKeyByDomainName[domainName] = newPrivKeyPair

	return req, nil
}

// RandomPolicyCertificate: generate one psr for one specific domain.
func (do *DomainOwner) RandomPolicyCertificate(domainName string, policy common.PolicyAttributes,
) (*common.PolicyCertificateSigningRequest, error) {

	rpcKeyPair, ok := do.privKeyByDomainName[domainName]
	if !ok {
		return nil, fmt.Errorf("RandomPolicyCertificate | No valid RPC for domain %s", domainName)
	}

	polCertSignReq := common.NewPolicyCertificateSigningRequest(
		0,          // version
		"",         // issuer
		domainName, // subject
		0,          // serial number
		domainName, // domain
		time.Now(),
		time.Now().Add(time.Microsecond), // not after
		false,                            // is issuer
		nil,                              // public key
		common.RSA,
		common.SHA256,
		time.Now(), // timestamp
		policy,     // policy attributes
		nil,        // owner's signature
		nil,        // owner pub key hash
	)

	err := crypto.SignAsOwner(rpcKeyPair, polCertSignReq)
	if err != nil {
		return nil, fmt.Errorf("RandomPolicyCertificate | DomainOwnerSignPSR | %w", err)
	}

	return polCertSignReq, nil
}

// generate new rsa key pair
func (do *DomainOwner) generateRSAPrivKeyPair() (*rsa.PrivateKey, error) {
	privateKeyPair, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generateRSAPrivKey | GenerateKey | %w", err)
	}
	return privateKeyPair, nil
}
