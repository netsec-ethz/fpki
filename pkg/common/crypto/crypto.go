package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"

	ctx509 "github.com/google/certificate-transparency-go/x509"

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
func SignAsOwner(ownerKey *rsa.PrivateKey, req *common.PolicyCertificateSigningRequest) error {
	// Clear owner signature (it's normally empty).
	req.OwnerSignature = nil

	// Identify the public key of the signer with its hash.
	// In CT, the hash of the public key is calculated over the DER-encoded
	// SubjectPublicKeyInfo object
	// From the MarshalPKIXPublicKey go docs:
	// MarshalPKIXPublicKey converts a public key to PKIX, ASN.1 DER form.
	// The encoded public key is a SubjectPublicKeyInfo structure
	// (see RFC 5280, Section 4.1).
	pubKeyBytes, err := ctx509.MarshalPKIXPublicKey(&ownerKey.PublicKey)
	if err != nil {
		return err
	}
	req.OwnerPubKeyHash = common.SHA256Hash(pubKeyBytes)

	// Sign using the owner's private key and including the hash of its public key.
	req.OwnerSignature, err = signStructRSASHA256(req, ownerKey)
	if err != nil {
		return fmt.Errorf("RCSRCreateSignature | SignStructRSASHA256 | %w", err)
	}

	return nil
}

// VerifyOwnerSignature verifies the owner's signature using the public key.
func VerifyOwnerSignature(req *common.PolicyCertificateSigningRequest,
	pubKey *rsa.PublicKey) error {

	// Serialize without signature:
	sig := req.OwnerSignature
	req.OwnerSignature = nil
	serializedStruct, err := common.ToJSON(req)
	if err != nil {
		return fmt.Errorf("RCSRVerifySignature | ToJSON | %w", err)
	}
	req.OwnerSignature = sig

	hashOutput := sha256.Sum256(serializedStruct)
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashOutput[:], req.OwnerSignature)
	if err != nil {
		return fmt.Errorf("RCSRVerifySignature | VerifyPKCS1v15 | %w", err)
	}
	return nil
}

func VerifyOwnerSignatureWithPolCert(req *common.PolicyCertificateSigningRequest,
	polCert *common.PolicyCertificate) error {

	// Serialize without signature:
	sig := req.OwnerSignature
	req.OwnerSignature = nil
	serializedStruct, err := common.ToJSON(req)
	if err != nil {
		return fmt.Errorf("RCSRVerifySignature | ToJSON | %w", err)
	}
	req.OwnerSignature = sig

	pubKey, err := util.DERBytesToRSAPublic(polCert.PublicKey)
	if err != nil {
		return err
	}

	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256,
		common.SHA256Hash(serializedStruct), req.OwnerSignature)
	if err != nil {
		return fmt.Errorf("RCSRVerifyRPCSignature | VerifyPKCS1v15 | %w", err)
	}

	return nil
}

// SignRequestAsIssuer is called by the Policy CA. It signs the request and generates a
// PolicyCertificate. The SPTs field is (should be) empty.
func SignRequestAsIssuer(req *common.PolicyCertificateSigningRequest, privKey *rsa.PrivateKey,
) (*common.PolicyCertificate, error) {

	// Create a certificate policy inheriting all values from the request.
	cert := common.NewPolicyCertificate(
		req.Version,
		req.Issuer,
		req.Subject(),
		req.SerialNumber(),
		req.NotBefore,
		req.NotAfter,
		req.IsIssuer,
		req.PublicKey,
		req.PublicKeyAlgorithm,
		req.SignatureAlgorithm,
		req.TimeStamp,
		req.PolicyAttributes,
		req.OwnerSignature,
		req.OwnerPubKeyHash,
		nil, // issuer signature
		nil, // issuer pub key hash
		nil, // SPTs
	)

	// Sign the policy certificate.
	signature, err := signStructRSASHA256(cert, privKey)
	if err != nil {
		return nil, fmt.Errorf("RCSRGenerateRPC | SignStructRSASHA256 | %w", err)
	}
	cert.IssuerSignature = signature

	return cert, nil
}

// SignPolicyCertificateAsIssuer is called by PCAs after they have received the SPTs from the
// CT log servers. The SPTs are embedded in the policy certificate passed to this function, and
// the PCA uses its key to create a signature. The policy certificate is passes with an empty
// IssuerSignature (this function does not remove IssuerSignature if it's set).
func SignPolicyCertificateAsIssuer(pc *common.PolicyCertificate, privKey *rsa.PrivateKey,
) (*common.PolicyCertificate, error) {

	signature, err := signStructRSASHA256(pc, privKey)
	if err != nil {
		return nil, err
	}
	pc.IssuerSignature = signature
	return pc, nil
}

// VerifyIssuerSignature: used by domain owner, check whether CA signature is correct
func VerifyIssuerSignature(caCert *ctx509.Certificate, rpc *common.PolicyCertificate) error {
	pubKey := caCert.PublicKey.(*rsa.PublicKey)

	// Serialize without CA signature or SPTs:
	caSig, SPTs := rpc.IssuerSignature, rpc.SPCTs
	rpc.IssuerSignature, rpc.SPCTs = nil, nil
	bytes, err := common.ToJSON(rpc)
	if err != nil {
		return fmt.Errorf("RCSRVerifySignature | ToJSON | %w", err)
	}
	rpc.IssuerSignature, rpc.SPCTs = caSig, SPTs

	hashOutput := sha256.Sum256(bytes)
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashOutput[:], rpc.IssuerSignature)
	if err != nil {
		return fmt.Errorf("RPCVerifyCASignature | VerifyPKCS1v15 | %w", err)
	}
	return nil
}

// signStructRSASHA256: generate a signature using SHA256 and RSA
func signStructRSASHA256(s any, key *rsa.PrivateKey) ([]byte, error) {
	b, err := common.ToJSON(s)
	if err != nil {
		return nil, fmt.Errorf("SignStructRSASHA256 | ToJSON | %w", err)
	}
	return SignBytes(b, key)
}
