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

// DomainOwner represents a domain owner. It contains a map of a domain to the latest domain root
// and its private key.
type DomainOwner struct {
	DomainRoots map[string]CertKey // My latest domain root pol. cert. per domain
}

type CertKey struct {
	Cert *common.PolicyCertificate
	Key  *rsa.PrivateKey
}

// NewDomainOwner: returns a new domain owner
func NewDomainOwner() *DomainOwner {
	return &DomainOwner{
		DomainRoots: make(map[string]CertKey),
	}
}

// GeneratePolCertSignRequest generates a Policy Certificate Signing Request for one domain.
// It will try to sign this request as an owner with an existing policy certificate.
// subject is the name of the domain: eg. fpki.com
func (do *DomainOwner) GeneratePolCertSignRequest(
	domainName string,
	version int,
) (*common.PolicyCertificateSigningRequest, error) {

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
		0,                                // serial number
		domainName,                       // domain
		time.Now(),                       // not before
		time.Now().Add(time.Microsecond), // not after
		false,                            // can issue
		false,                            // can own
		pubKeyBytes,                      // public key
		common.RSA,
		common.SHA256,
		time.Now(),                // timestamp
		common.PolicyAttributes{}, // policy attributes
		nil,                       // owner signature
		nil,                       // owner pub key hash
	)

	// if domain owner still have the private key of the previous RPC -> can avoid cool-off period
	if prevRoot, ok := do.DomainRoots[domainName]; ok {
		err = crypto.SignAsOwner(prevRoot.Cert, prevRoot.Key, req)
		if err != nil {
			return nil, fmt.Errorf("GeneratePolCertSignRequest | RCSRGenerateRPCSignature | %w", err)
		}
	}

	return req, nil
}

// generate new rsa key pair
func (do *DomainOwner) generateRSAPrivKeyPair() (*rsa.PrivateKey, error) {
	privateKeyPair, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generateRSAPrivKey | GenerateKey | %w", err)
	}
	return privateKeyPair, nil
}
