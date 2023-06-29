package common

import (
	"time"
)

// PolicyCertificateSigningRequest is a policy certificate signing request.
type PolicyCertificateSigningRequest struct {
	PolicyCertificateFields
}

type PolicyCertificateRevocationSigningRequest struct {
	Subject string `json:",omitemptyu"`
}

func NewPolicyCertificateSigningRequest(
	version int,
	issuer string,
	subject string,
	serialNumber int,
	notBefore time.Time,
	notAfter time.Time,
	isIssuer bool,
	publicKey []byte,
	publicKeyAlgorithm PublicKeyAlgorithm,
	signatureAlgorithm SignatureAlgorithm,
	timeStamp time.Time,
	policyAttributes []PolicyAttributes,
	ownerSignature []byte,
	ownerPubKeyHash []byte,
) *PolicyCertificateSigningRequest {

	return &PolicyCertificateSigningRequest{
		PolicyCertificateFields: *NewPolicyCertificateFields(
			version,
			issuer,
			subject,
			serialNumber,
			notBefore,
			notAfter,
			isIssuer,
			publicKey,
			publicKeyAlgorithm,
			signatureAlgorithm,
			timeStamp,
			policyAttributes,
			ownerSignature,
			ownerPubKeyHash,
		),
	}
}

func (req *PolicyCertificateSigningRequest) Equal(x *PolicyCertificateSigningRequest) bool {
	return req.PolicyCertificateFields.Equal(x.PolicyCertificateFields)
}
