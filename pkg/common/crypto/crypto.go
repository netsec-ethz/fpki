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
func SignAsOwner(domainOwnerPrivKey *rsa.PrivateKey, req *common.PolicyCertificateSigningRequest) error {
	// clear signature; normally should be empty
	req.OwnerSignature = []byte{}

	signature, err := signStructRSASHA256(req, domainOwnerPrivKey)
	if err != nil {
		return fmt.Errorf("RCSRCreateSignature | SignStructRSASHA256 | %w", err)
	}

	req.OwnerSignature = signature
	return nil
}

// VerifyOwnerSignature verifies the owner's signature using the public key.
func VerifyOwnerSignature(req *common.PolicyCertificateSigningRequest) error {
	// Serialize without signature:
	sig := req.OwnerSignature
	req.OwnerSignature = nil
	serializedStruct, err := common.ToJSON(req)
	if err != nil {
		return fmt.Errorf("RCSRVerifySignature | ToJSON | %w", err)
	}
	req.OwnerSignature = sig

	// Get the pub key:
	pubKey, err := util.PEMToRSAPublic(req.PublicKey)
	if err != nil {
		return fmt.Errorf("RCSRVerifySignature | PemBytesToRsaPublicKey | %w", err)
	}

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

	pubKey, err := util.PEMToRSAPublic(polCert.PublicKey)
	if err != nil {
		return fmt.Errorf("RCSRVerifyRPCSignature | PemBytesToRsaPublicKey | %w", err)
	}

	hashOutput := sha256.Sum256(serializedStruct)
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashOutput[:], req.OwnerSignature)
	if err != nil {
		return fmt.Errorf("RCSRVerifyRPCSignature | VerifyPKCS1v15 | %w", err)
	}

	return nil
}

// SignAsIssuer is called by the Policy CA. It signs the request and generates a
// PolicyCertificate. The SPTs field is (should be) empty.
func SignAsIssuer(req *common.PolicyCertificateSigningRequest, privKey *rsa.PrivateKey,
) (*common.PolicyCertificate, error) {

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
		nil, // issuer signature
		nil, // SPTs
	)

	signature, err := signStructRSASHA256(cert, privKey)
	if err != nil {
		return nil, fmt.Errorf("RCSRGenerateRPC | SignStructRSASHA256 | %w", err)
	}

	cert.IssuerSignature = signature
	return cert, nil
}

// VerifyIssuerSignature: used by domain owner, check whether CA signature is correct
func VerifyIssuerSignature(caCert *ctx509.Certificate, rpc *common.PolicyCertificate) error {
	pubKey := caCert.PublicKey.(*rsa.PublicKey)

	// Serialize without CA signature or SPTs:
	caSig, SPTs := rpc.IssuerSignature, rpc.SPTs
	rpc.IssuerSignature, rpc.SPTs = nil, nil
	bytes, err := common.ToJSON(rpc)
	if err != nil {
		return fmt.Errorf("RCSRVerifySignature | ToJSON | %w", err)
	}
	rpc.IssuerSignature, rpc.SPTs = caSig, SPTs

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
