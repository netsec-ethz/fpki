package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/util"
)

func SignPolicyCertificateTimestamp(
	pc *common.PolicyCertificate,
	version int,
	logId []byte,
	key *rsa.PrivateKey,
) (*common.SignedPolicyCertificateTimestamp, error) {

	serializedPc, err := common.ToJSON(pc)
	if err != nil {
		return nil, fmt.Errorf("SignSPT | SerializePC | %w", err)
	}

	spt := common.NewSignedPolicyCertificateTimestamp(version, logId, time.Now(), nil)
	signatureInput := common.NewSignedEntryTimestampSignatureInput(serializedPc, spt)
	serializedSpt, err := common.ToJSON(signatureInput)
	if err != nil {
		return nil, fmt.Errorf("SignSPT | SerializeSPTInput | %w", err)
	}

	signature, err := SignBytes(serializedSpt, key)
	if err != nil {
		return nil, fmt.Errorf("SignSPT | Sign | %w", err)
	}

	spt.Signature = signature
	return spt, nil
}

func SignBytes(b []byte, key *rsa.PrivateKey) ([]byte, error) {
	hashOutput := sha256.Sum256(b)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashOutput[:])
	if err != nil {
		return nil, fmt.Errorf("SignBytes | SignPKCS1v15 | %w", err)
	}
	return signature, nil
}

func VerifySignedBytes(b []byte, signature []byte, key *rsa.PublicKey) error {
	hashOutput := sha256.Sum256(b)
	err := rsa.VerifyPKCS1v15(key, crypto.SHA256, hashOutput[:], signature)
	if err != nil {
		return fmt.Errorf("VerifySignature | VerifyPKCS1V15 | %w", err)
	}
	return nil
}

// SignAsOwner generates a signature using the owner's key, and fills the owner signature in
// the policy certificate signing request.
//
// The request is modified in-place iff no errors are found.
func SignAsOwner(
	ownerPolCert *common.PolicyCertificate,
	ownerKey *rsa.PrivateKey,
	req *common.PolicyCertificateSigningRequest,
) error {

	if req.OwnerSignature != nil || req.OwnerHash != nil {
		return fmt.Errorf("there exists a non nil owner signature and hash")
	}
	if !ownerPolCert.CanOwn {
		return fmt.Errorf("the owner certificate cannot sign as owner")
	}
	// Owner identifier:
	ownerHash, err := ComputeHashAsSigner(ownerPolCert)
	if err != nil {
		return err
	}
	req.OwnerHash = ownerHash

	// Sign using the owner's private key and including the hash of its public key.
	ownerSignature, err := signStructRSASHA256(common.NewPolicyCertificateFromRequest(req), ownerKey)
	if err != nil {
		req.OwnerHash = nil
		return fmt.Errorf("RCSRCreateSignature | SignStructRSASHA256 | %w", err)
	}

	// No errors. Modify the request in-place.
	req.OwnerSignature = ownerSignature

	return nil
}

// VerifyOwnerSignature verifies the owner's signature using the public key.
func VerifyOwnerSignature(
	ownerPolCert *common.PolicyCertificate,
	req *common.PolicyCertificateSigningRequest,
) error {

	return VerifyOwnerSignatureInPolicyCertificate(
		ownerPolCert,
		common.NewPolicyCertificateFromRequest(req))
}

func VerifyOwnerSignatureInPolicyCertificate(
	ownerPolCert *common.PolicyCertificate,
	c *common.PolicyCertificate,
) error {

	// Check owner identification.
	ownerHash, err := ComputeHashAsSigner(ownerPolCert)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(c.OwnerHash, ownerHash) != 1 {
		// Not equal.
		return fmt.Errorf("request's owner is identified by %s, but policy certificate is %s",
			hex.EncodeToString(c.OwnerHash), hex.EncodeToString(ownerHash))
	}

	// Reconstruct owner's public key.
	pubKey, err := util.DERBytesToRSAPublic(ownerPolCert.PublicKey)
	if err != nil {
		return err
	}

	// Serialize owned pol cert without SPCTs, issuer signature, issuer hash, and owner signature:
	SPCTs, issuerSignature, issuerHash, ownerSignature :=
		c.SPCTs, c.IssuerSignature, c.IssuerHash, c.OwnerSignature
	c.SPCTs, c.IssuerSignature, c.IssuerHash, c.OwnerSignature = nil, nil, nil, nil
	serializedStruct, err := common.ToJSON(c)
	if err != nil {
		return fmt.Errorf("RCSRVerifySignature | ToJSON | %w", err)
	}
	c.SPCTs, c.IssuerSignature, c.IssuerHash, c.OwnerSignature =
		SPCTs, issuerSignature, issuerHash, ownerSignature // restore previous values

	// Hash serialized request and check the signature with the owner's public key.
	hashOutput := sha256.Sum256(serializedStruct)
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashOutput[:], c.OwnerSignature)
	if err != nil {
		return fmt.Errorf("bad owner signature: %w", err)
	}

	return nil
}

// SignRequestAsIssuer is called by the Policy CA. It signs the request and generates a
// PolicyCertificate. The SPTs field is (should be) empty.
func SignRequestAsIssuer(
	issuerPolCert *common.PolicyCertificate,
	privKey *rsa.PrivateKey,
	req *common.PolicyCertificateSigningRequest,
) (*common.PolicyCertificate, error) {

	// Create a certificate policy inheriting all values from the request.
	cert := common.NewPolicyCertificate(
		req.Version,
		req.SerialNumber(),
		req.DomainField,
		req.NotBefore,
		req.NotAfter,
		req.CanIssue,
		req.CanOwn,
		req.PublicKey,
		req.PublicKeyAlgorithm,
		req.SignatureAlgorithm,
		req.TimeStamp,
		req.PolicyAttributes,
		req.OwnerSignature,
		req.OwnerHash,
		nil, // SPTs
		nil, // issuer signature
		nil, // issuer hash
	)

	err := SignPolicyCertificateAsIssuer(issuerPolCert, privKey, cert)
	return cert, err
}

// SignPolicyCertificateAsIssuer is called by PCAs after they have received the SPTs from the
// CT log servers. The SPTs are embedded in the policy certificate passed to this function, and
// the PCA uses its key to create a signature. The policy certificate is passes with an empty
// IssuerSignature (this function does not remove IssuerSignature if it's set).
//
// The  childPolCert policy certificate is modified in place iif no error is found.
func SignPolicyCertificateAsIssuer(
	issuerPolCert *common.PolicyCertificate,
	privKey *rsa.PrivateKey,
	childPolCert *common.PolicyCertificate,
) error {

	if childPolCert.IssuerSignature != nil || childPolCert.IssuerHash != nil {
		return fmt.Errorf("remove any issuer signature or issuer hash before signing (set to nil)")
	}
	// Identify the issuer of the child policy certificate with the hash of the modified policy
	// certificate of the issuer.
	issuerHash, err := ComputeHashAsSigner(issuerPolCert)
	if err != nil {
		return err
	}
	childPolCert.IssuerHash = issuerHash

	// Sign the child policy certificate.
	signature, err := signStructRSASHA256(childPolCert, privKey)
	if err != nil {
		childPolCert.IssuerHash = nil
		return err
	}

	// No errors: modify the child policy certificate in-place.
	childPolCert.IssuerSignature = signature

	return nil
}

// VerifyIssuerConstraints verifies various constraints given by the issuer policy certificate
// and returns the first violated constraint, or nil if no constraints were violated.
func VerifyIssuerConstraints(
	issuerPolCert *common.PolicyCertificate,
	childPolCert *common.PolicyCertificate,
) error {

	// check validity period
	if childPolCert.NotBefore.Before(issuerPolCert.NotBefore) {
		return fmt.Errorf("policy certificate is valid before its issuer certificate (%v < %v)", childPolCert.NotBefore, issuerPolCert.NotBefore)
	}
	if issuerPolCert.NotAfter.Before(childPolCert.NotAfter) {
		return fmt.Errorf("policy certificate is valid after its issuer certificate (%v > %v)", childPolCert.NotAfter, issuerPolCert.NotAfter)
	}

	// check domain constraint
	// TODO (cyrill): could also check with public suffix list
	validDomainName := regexp.MustCompile("([^.]+\\.)*([^.]+\\.?)?")
	if !validDomainName.Match([]byte(childPolCert.DomainField)) {
		return fmt.Errorf("Policy Certificate does not have a valid domain name: %s", childPolCert.DomainField)
	}
	if !validDomainName.Match([]byte(issuerPolCert.DomainField)) {
		return fmt.Errorf("Issuer Policy Certificate does not have a valid domain name: %s", issuerPolCert.DomainField)
	}
	if issuerPolCert.DomainField != "" {
		// all domain fields are accepted
	} else if issuerPolCert.DomainField == childPolCert.DomainField {
		// identical domain fields are accepted
	} else {
		if !strings.HasSuffix(childPolCert.DomainField, "."+issuerPolCert.DomainField) {
			return fmt.Errorf("Policy certificate is not a subdomain of the issuer policy certificate")
		} else {
			// is valid subdomain
		}
	}

	return nil
}

// VerifyIssuerSignature: used by domain owner, check whether CA signature is correct
func VerifyIssuerSignature(
	issuerPolCert *common.PolicyCertificate,
	childPolCert *common.PolicyCertificate,
) error {

	// Check owner identification.
	issuerHash, err := ComputeHashAsSigner(issuerPolCert)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(childPolCert.IssuerHash, issuerHash) != 1 {
		// Not equal.
		return fmt.Errorf("policy certificate's issuer is identified by %s, but "+
			"policy certificate is %s",
			hex.EncodeToString(childPolCert.IssuerHash), hex.EncodeToString(issuerHash))
	}

	// Reconstruct issuer's public key.
	pubKey, err := util.DERBytesToRSAPublic(issuerPolCert.PublicKey)
	if err != nil {
		return err
	}

	// Serialize child cert without signature:
	sig := childPolCert.IssuerSignature
	childPolCert.IssuerSignature = nil
	serializedStruct, err := common.ToJSON(childPolCert)
	if err != nil {
		return err
	}
	childPolCert.IssuerSignature = sig // restore previous signature

	// Hash serialized request and check the signature with the owner's public key.
	hashOutput := common.SHA256Hash(serializedStruct)
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashOutput, childPolCert.IssuerSignature)
	if err != nil {
		return fmt.Errorf("bad owner signature: %w", err)
	}

	return nil

}

// signStructRSASHA256: generate a signature using SHA256 and RSA
func signStructRSASHA256(s any, key *rsa.PrivateKey) ([]byte, error) {
	data, err := common.ToJSON(s)
	if err != nil {
		return nil, fmt.Errorf("SignStructRSASHA256 | ToJSON | %w", err)
	}

	return SignBytes(data, key)
}

// ComputeHashAsSigner computes the bytes of the policy certificate as being an owner certificate.
// This means: it serializes it but without SPCTs or issuer signature, and computes its sha256.
func ComputeHashAsSigner(p *common.PolicyCertificate) ([]byte, error) {
	// Remove SPCTs and issuer signature.
	SPCTs, issuerSignature := p.SPCTs, p.IssuerSignature
	p.SPCTs, p.IssuerSignature = nil, nil

	// Serialize and restore previously removed fields.
	serializedPC, err := common.ToJSON(p)
	p.SPCTs, p.IssuerSignature = SPCTs, issuerSignature

	return common.SHA256Hash(serializedPC), err
}
