package common

import (
	"bytes"
	"time"
)

// PolicyCertificateSigningRequest is a policy certificate signing request.
type PolicyCertificateSigningRequest struct {
	PolicyCertificateFields
}

func (o PolicyCertificateSigningRequest) Raw() ([]byte, error) {
	return rawTemplate(o)
}

// PolicyCertificateRevocationSigningRequest is a request to prepare a revocation.
// The hash of the certificate intended to be revoked must be computed without any SPCT and
// issuer signature (i.e. SPCT independent).
type PolicyCertificateRevocationSigningRequest struct {
	PolicyCertificateHash []byte `json:",omitempty"` // Hash of the pol. cert. to revoke
}

func NewPolicyCertificateSigningRequest(
	version int,
	serialNumber int,
	domain string,
	notBefore time.Time,
	notAfter time.Time,
	canIssue bool,
	canOwn bool,
	publicKey []byte,
	publicKeyAlgorithm PublicKeyAlgorithm,
	signatureAlgorithm SignatureAlgorithm,
	timeStamp time.Time,
	policyAttributes PolicyAttributes,
	ownerSignature []byte,
	ownerHash []byte,
) *PolicyCertificateSigningRequest {

	return &PolicyCertificateSigningRequest{
		PolicyCertificateFields: *NewPolicyCertificateFields(
			version,
			serialNumber,
			domain,
			notBefore,
			notAfter,
			canIssue,
			canOwn,
			publicKey,
			publicKeyAlgorithm,
			signatureAlgorithm,
			timeStamp,
			policyAttributes,
			ownerSignature,
			ownerHash,
		),
	}
}

func (req *PolicyCertificateSigningRequest) Equal(x *PolicyCertificateSigningRequest) bool {
	return req.PolicyCertificateFields.Equal(x.PolicyCertificateFields)
}

func NewPolicyCertificateRevocationSigningRequest(
	polCertHash []byte,
) *PolicyCertificateRevocationSigningRequest {
	return &PolicyCertificateRevocationSigningRequest{
		PolicyCertificateHash: polCertHash,
	}
}

func (req *PolicyCertificateRevocationSigningRequest) Equal(
	x *PolicyCertificateRevocationSigningRequest,
) bool {

	return bytes.Equal(req.PolicyCertificateHash, x.PolicyCertificateHash)

}
