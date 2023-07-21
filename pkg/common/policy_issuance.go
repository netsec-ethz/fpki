package common

import (
	"bytes"
	"time"
)

// PolicyCertificateSigningRequest is a policy certificate signing request.
type PolicyCertificateSigningRequest struct {
	PolicyCertificateFields
}

type PolicyCertificateRevocationSigningRequest struct {
	PolicyCertificateHash []byte `json:",omitempty"` // Hash of the pol. cert. to revoke
}

func NewPolicyCertificateSigningRequest(
	version int,
	serialNumber int,
	domain string,
	notBefore time.Time,
	notAfter time.Time,
	isIssuer bool,
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
			isIssuer,
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
