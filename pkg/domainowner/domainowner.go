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

// GenerateRCSR: Generate a Root Certificate Signing Request for one domain
// subject is the name of the domain: eg. fpki.com
func (do *DomainOwner) GenerateRCSR(domainName string, version int) (*common.RCSR, error) {
	// generate a fresh RSA key pair; new RSA key for every RCSR, thus every RPC
	newPrivKeyPair, err := do.generateRSAPrivKeyPair()
	if err != nil {
		return nil, fmt.Errorf("GenerateRCSR | generateRSAPrivKey | %w", err)
	}

	// marshall public key into bytes
	pubKeyBytes, err := util.RSAPublicToPEM(&newPrivKeyPair.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("GenerateRCSR | RsaPublicKeyToPemBytes | %w", err)
	}

	rcsr := common.NewRCSR(
		domainName,
		version,
		time.Now(),
		common.RSA,
		pubKeyBytes,
		common.SHA256,
		nil,
		nil,
	)

	// if domain owner still have the private key of the previous RPC -> can avoid cool-off period
	if prevKey, ok := do.privKeyByDomainName[domainName]; ok {
		err = crypto.RCSRGenerateRPCSignature(rcsr, prevKey)
		if err != nil {
			return nil, fmt.Errorf("GenerateRCSR | RCSRGenerateRPCSignature | %w", err)
		}
	}

	// generate signature for RCSR, using the new pub key
	err = crypto.RCSRCreateSignature(newPrivKeyPair, rcsr)
	if err != nil {
		return nil, fmt.Errorf("GenerateRCSR | RCSRCreateSignature | %w", err)
	}

	do.privKeyByDomainName[domainName] = newPrivKeyPair

	return rcsr, nil
}

// GeneratePSR: generate one psr for one specific domain.
func (do *DomainOwner) GeneratePSR(domainName string, policy common.DomainPolicy) (*common.PSR, error) {
	rpcKeyPair, ok := do.privKeyByDomainName[domainName]
	if !ok {
		return nil, fmt.Errorf("GeneratePSR | No valid RPC for domain %s", domainName)
	}

	psr := &common.PSR{
		PolicyIssuerBase: common.PolicyIssuerBase{
			RawSubject: domainName,
		},
		Policy:    policy,
		TimeStamp: time.Now(),
	}

	err := crypto.DomainOwnerSignPSR(rpcKeyPair, psr)
	if err != nil {
		return nil, fmt.Errorf("GeneratePSR | DomainOwnerSignPSR | %w", err)
	}

	return psr, nil
}

// generate new rsa key pair
func (do *DomainOwner) generateRSAPrivKeyPair() (*rsa.PrivateKey, error) {
	privateKeyPair, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generateRSAPrivKey | GenerateKey | %w", err)
	}
	return privateKeyPair, nil
}
