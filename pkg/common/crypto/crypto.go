package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/util"
)

func SignBytes(b []byte, key *rsa.PrivateKey) ([]byte, error) {
	hashOutput := sha256.Sum256(b)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashOutput[:])
	if err != nil {
		return nil, fmt.Errorf("SignBytes | SignPKCS1v15 | %w", err)
	}
	return signature, nil
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
	// Owner identifier:
	ownerHash, err := ComputeHashAsOwner(ownerPolCert)
	if err != nil {
		return err
	}
	req.OwnerHash = ownerHash

	// Sign using the owner's private key and including the hash of its public key.
	ownerSignature, err := signStructRSASHA256(req, ownerKey)
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

	// Check owner identification.
	ownerHash, err := ComputeHashAsOwner(ownerPolCert)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(req.OwnerHash, ownerHash) != 1 {
		// Not equal.
		return fmt.Errorf("request's owner is identified by %s, but policy certificate is %s",
			hex.EncodeToString(req.OwnerHash), hex.EncodeToString(ownerHash))
	}

	// Reconstruct owner's public key.
	pubKey, err := util.DERBytesToRSAPublic(ownerPolCert.PublicKey)
	if err != nil {
		return err
	}

	// Serialize request without signature:
	sig := req.OwnerSignature
	req.OwnerSignature = nil
	serializedStruct, err := common.ToJSON(req)
	if err != nil {
		return fmt.Errorf("RCSRVerifySignature | ToJSON | %w", err)
	}
	req.OwnerSignature = sig // restore previous signature

	// Hash serialized request and check the signature with the owner's public key.
	hashOutput := sha256.Sum256(serializedStruct)
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashOutput[:], req.OwnerSignature)
	if err != nil {
		return fmt.Errorf("bad owner signature: %w", err)
	}

	return nil
}

func VerifyOwnerSignatureInPolicyCertificate(
	ownerPolCert *common.PolicyCertificate,
	c *common.PolicyCertificate,
) error {

	req := common.NewPolicyCertificateSigningRequest(
		c.Version,
		c.RawSerialNumber,
		c.RawDomain,
		c.NotBefore,
		c.NotAfter,
		c.IsIssuer,
		c.PublicKey,
		c.PublicKeyAlgorithm,
		c.SignatureAlgorithm,
		c.TimeStamp,
		c.PolicyAttributes,
		c.OwnerSignature,
		c.OwnerHash,
	)
	return VerifyOwnerSignature(ownerPolCert, req)
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
		req.RawDomain,
		req.NotBefore,
		req.NotAfter,
		req.IsIssuer,
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
	issuerHash, err := ComputeHashAsIssuer(issuerPolCert)
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

// VerifyIssuerSignature: used by domain owner, check whether CA signature is correct
func VerifyIssuerSignature(
	issuerPolCert *common.PolicyCertificate,
	childPolCert *common.PolicyCertificate,
) error {

	// Check owner identification.
	issuerHash, err := ComputeHashAsIssuer(issuerPolCert)
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

// ComputeHashAsOwner computes the bytes of the policy certificate as being an owner certificate.
// This means: it serializes it but without SPCTs or issuer signature, and computes its sha256.
func ComputeHashAsOwner(p *common.PolicyCertificate) ([]byte, error) {
	// Remove SPCTs and issuer signature.
	SPCTs, issuerSignature := p.SPCTs, p.IssuerSignature
	p.SPCTs, p.IssuerSignature = nil, nil

	// Serialize and restore previously removed fields.
	serializedPC, err := common.ToJSON(p)
	p.SPCTs, p.IssuerSignature = SPCTs, issuerSignature

	return common.SHA256Hash(serializedPC), err
}

func ComputeHashAsIssuer(p *common.PolicyCertificate) ([]byte, error) {
	// Remove SPCTs.
	SPCTs := p.SPCTs
	p.SPCTs = nil

	// Serialize and restore previously removed fields.
	serializedPC, err := common.ToJSON(p)
	p.SPCTs = SPCTs

	return common.SHA256Hash(serializedPC), err
}
