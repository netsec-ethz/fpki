package common

import (
	"bytes"
	"time"
)

// PolicyDocument is any policy document that can be exchanged among mapservers, CT log servers,
// and others.
type PolicyDocument interface {
	PolicyPart
	SerialNumber() int
	Domain() string
}

type PolicyCertificateBase struct {
	PolicyPartBase
	RawSerialNumber int    `json:"SerialNumber,omitempty"`
	RawDomain       string `json:"Domain,omitempty"`
}

func (o PolicyCertificateBase) SerialNumber() int { return o.RawSerialNumber }
func (o PolicyCertificateBase) Domain() string    { return o.RawDomain }
func (p PolicyCertificateBase) Equal(x PolicyCertificateBase) bool {
	return p.PolicyPartBase.Equal(x.PolicyPartBase) &&
		p.RawSerialNumber == x.RawSerialNumber &&
		p.RawDomain == x.RawDomain
}

// PolicyCertificateFields contains all the fields that a policy certificate or a signing request
// have in common. This excudes e.g. the issuer signature and hash.
//
// The `PublicKey` field is the DER-encoded SubjectPublicKeyInfo, as returned by the call
// `x509.MarshalPKIXPublicKey` in the `crypto/x509` package.
// From the `MarshalPKIXPublicKey` go docs:
// MarshalPKIXPublicKey converts a public key to PKIX, ASN.1 DER form.
// The encoded public key is a SubjectPublicKeyInfo structure
// (see RFC 5280, Section 4.1).
//
// The `OwnerHash` field is the SHA256 of the payload of the owner certificate that contained the
// owner signature. The hash is computed on the owner's policy certificate, but without any
// SPCTs or issuer signature, but preserving the owner's signature.
type PolicyCertificateFields struct {
	PolicyCertificateBase
	NotBefore          time.Time          `json:",omitempty"`
	NotAfter           time.Time          `json:",omitempty"`
	IsIssuer           bool               `json:",omitempty"`
	PublicKey          []byte             `json:",omitempty"`
	PublicKeyAlgorithm PublicKeyAlgorithm `json:",omitempty"`
	SignatureAlgorithm SignatureAlgorithm `json:",omitempty"`
	TimeStamp          time.Time          `json:",omitempty"`
	PolicyAttributes   PolicyAttributes   `json:",omitempty"`
	OwnerSignature     []byte             `json:",omitempty"`
	OwnerHash          []byte             `json:",omitempty"`
}

// PolicyCertificate can be a Root Policy Certificate, or a policy certificate that was issued by
// a previously existing policy certificate.
// The field `IssuerHash` has semantics analogouys to `OwnerHash`: it is the SHA256 of the issuer
// policy certificate that was used to sign this policy certificate, without SCPTs.
type PolicyCertificate struct {
	PolicyCertificateFields
	IssuerSignature []byte                             `json:",omitempty"`
	IssuerHash      []byte                             `json:",omitempty"`
	SPCTs           []SignedPolicyCertificateTimestamp `json:",omitempty"`
}

// PolicyAttributes is a domain policy that specifies what is or not acceptable for a domain.
type PolicyAttributes struct {
	TrustedCA         []string `json:",omitempty"`
	AllowedSubdomains []string `json:",omitempty"`
}

type PolicyCertificateRevocationFields struct {
	PolicyCertificateBase
	TimeStamp      time.Time `json:",omitempty"`
	OwnerSignature []byte    `json:",omitempty"`
	OwnerHash      []byte    `json:",omitempty"`
}

type PolicyCertificateRevocation struct {
	PolicyCertificateRevocationFields
	IssuerSignature []byte `json:",omitempty"`
	// Hash of the issuer's cert w/out SPCTs:
	IssuerHash []byte                                       `json:",omitempty"`
	SPCRTs     []SignedPolicyCertificateRevocationTimestamp `json:",omitempty"`
}

func NewPolicyCertificateFields(
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
) *PolicyCertificateFields {
	return &PolicyCertificateFields{
		PolicyCertificateBase: PolicyCertificateBase{
			PolicyPartBase: PolicyPartBase{
				Version: version,
			},
			RawSerialNumber: serialNumber,
			RawDomain:       domain,
		},
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		IsIssuer:           isIssuer,
		PublicKey:          publicKey,
		PublicKeyAlgorithm: publicKeyAlgorithm,
		SignatureAlgorithm: signatureAlgorithm,
		TimeStamp:          timeStamp,
		PolicyAttributes:   policyAttributes,
		OwnerSignature:     ownerSignature,
		OwnerHash:          ownerHash,
	}
}

func (c PolicyCertificateFields) Equal(x PolicyCertificateFields) bool {
	return c.PolicyCertificateBase.Equal(x.PolicyCertificateBase) &&
		c.PublicKeyAlgorithm == x.PublicKeyAlgorithm &&
		bytes.Equal(c.PublicKey, x.PublicKey) &&
		c.NotBefore.Equal(x.NotBefore) &&
		c.NotAfter.Equal(x.NotAfter) &&
		c.SignatureAlgorithm == x.SignatureAlgorithm &&
		c.TimeStamp.Equal(x.TimeStamp) &&
		bytes.Equal(c.OwnerSignature, x.OwnerSignature) &&
		bytes.Equal(c.OwnerHash, x.OwnerHash) &&
		c.PolicyAttributes.Equal(x.PolicyAttributes)
}

func NewPolicyCertificate(
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
	SPTs []SignedPolicyCertificateTimestamp,
	issuerSignature []byte,
	issuerHash []byte,
) *PolicyCertificate {

	return &PolicyCertificate{
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
		IssuerSignature: issuerSignature,
		IssuerHash:      issuerHash,
		SPCTs:           SPTs,
	}
}

func (c PolicyCertificate) Equal(x PolicyCertificate) bool {
	return c.PolicyCertificateFields.Equal(x.PolicyCertificateFields) &&
		bytes.Equal(c.IssuerSignature, x.IssuerSignature) &&
		bytes.Equal(c.IssuerHash, x.IssuerHash) &&
		equalSlices(c.SPCTs, x.SPCTs)
}

func (s PolicyAttributes) Equal(o PolicyAttributes) bool {
	return true &&
		equalStringSlices(s.TrustedCA, o.TrustedCA) &&
		equalStringSlices(s.AllowedSubdomains, o.AllowedSubdomains)
}

func NewPolicyCertificateRevocationFields(
	version int,
	serialNumber int,
	timeStamp time.Time,
	ownerSignature []byte,
	ownerHash []byte,
) *PolicyCertificateRevocationFields {
	return &PolicyCertificateRevocationFields{
		PolicyCertificateBase: PolicyCertificateBase{
			PolicyPartBase: PolicyPartBase{
				Version: version,
			},
			RawSerialNumber: serialNumber,
		},
		TimeStamp:      timeStamp,
		OwnerSignature: ownerSignature,
		OwnerHash:      ownerHash,
	}
}

func (c PolicyCertificateRevocationFields) Equal(x PolicyCertificateRevocationFields) bool {
	return c.PolicyCertificateBase.Equal(x.PolicyCertificateBase) &&
		c.TimeStamp == x.TimeStamp &&
		bytes.Equal(c.OwnerSignature, x.OwnerSignature) &&
		bytes.Equal(c.OwnerHash, x.OwnerHash)
}

func NewPolicyCertificateRevocation(
	version int,
	serialNumber int,
	timeStamp time.Time,
	ownerSignature []byte,
	ownerHash []byte,
	serverTimestamps []SignedPolicyCertificateRevocationTimestamp,
	issuerSignature []byte,
	issuerHash []byte,
) *PolicyCertificateRevocation {
	return &PolicyCertificateRevocation{
		PolicyCertificateRevocationFields: *NewPolicyCertificateRevocationFields(
			version,
			serialNumber,
			timeStamp,
			ownerSignature,
			ownerHash,
		),
		IssuerSignature: issuerSignature,
		IssuerHash:      issuerHash,
		SPCRTs:          serverTimestamps,
	}
}

func (r PolicyCertificateRevocation) Equal(x PolicyCertificateRevocation) bool {
	return r.PolicyCertificateRevocationFields.Equal(x.PolicyCertificateRevocationFields) &&
		bytes.Equal(r.IssuerSignature, x.IssuerSignature) &&
		bytes.Equal(r.IssuerHash, x.IssuerHash) &&
		equalSlices(r.SPCRTs, x.SPCRTs)
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

type Equaler[T any] interface {
	Equal(T) bool
}

// equalSlices (a,b) returns true iff the a and b slices contain exactly the same elements and in
// the same order, using `Equal` on each element to compare them.
func equalSlices[T Equaler[T]](a, b []T) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}
