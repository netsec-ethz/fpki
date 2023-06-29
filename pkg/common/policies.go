package common

import (
	"bytes"
	"time"
)

// PolicyDocument is any policy document that can be exchanged among mapservers, CT log servers,
// and others.
type PolicyDocument interface {
	PolicyPart
	Subject() string
	SerialNumber() int
}

type PolicyCertificateBase struct {
	PolicyPartBase
	RawSubject      string `json:"Subject,omitempty"`
	RawSerialNumber int    `json:"SerialNumber,omitempty"`
}

func (o PolicyCertificateBase) Subject() string   { return o.RawSubject }
func (o PolicyCertificateBase) SerialNumber() int { return o.RawSerialNumber }
func (p PolicyCertificateBase) Equal(x PolicyCertificateBase) bool {
	return p.PolicyPartBase.Equal(x.PolicyPartBase) &&
		p.RawSubject == x.RawSubject &&
		p.RawSerialNumber == x.RawSerialNumber
}

type PolicyCertificateFields struct {
	PolicyCertificateBase
	Domain             string             `json:",omitempty"`
	NotBefore          time.Time          `json:",omitempty"`
	NotAfter           time.Time          `json:",omitempty"`
	IsIssuer           bool               `json:",omitempty"`
	PublicKey          []byte             `json:",omitempty"` // DER-encoded SubjectPublicKeyInfo
	PublicKeyAlgorithm PublicKeyAlgorithm `json:",omitempty"`
	SignatureAlgorithm SignatureAlgorithm `json:",omitempty"`
	TimeStamp          time.Time          `json:",omitempty"`
	PolicyAttributes   PolicyAttributes   `json:",omitempty"`
	OwnerSignature     []byte             `json:",omitempty"`
	OwnerPubKeyHash    []byte             `json:",omitempty"` // SHA256 of owner's public key
}

// PolicyCertificate is a Root Policy Certificate.
type PolicyCertificate struct {
	PolicyCertificateFields
	IssuerSignature  []byte                             `json:",omitempty"`
	IssuerPubKeyHash []byte                             `json:",omitempty"`
	SPCTs            []SignedPolicyCertificateTimestamp `json:",omitempty"`
}

// PolicyAttributes is a domain policy that specifies what is or not acceptable for a domain.
type PolicyAttributes struct {
	TrustedCA         []string `json:",omitempty"`
	AllowedSubdomains []string `json:",omitempty"`
}

type PolicyCertificateRevocationFields struct {
	PolicyCertificateBase
	TimeStamp       time.Time `json:",omitempty"`
	OwnerSignature  []byte    `json:",omitempty"`
	OwnerPubKeyHash []byte    `json:",omitempty"` // SHA256 of owner's public key
}

type PolicyCertificateRevocation struct {
	PolicyCertificateRevocationFields
	IssuerSignature  []byte                                       `json:",omitempty"`
	IssuerPubKeyHash []byte                                       `json:",omitempty"`
	SPCRTs           []SignedPolicyCertificateRevocationTimestamp `json:",omitempty"`
}

func NewPolicyCertificateFields(
	version int,
	issuer string,
	subject string,
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
	ownerPubKeyHash []byte,
) *PolicyCertificateFields {
	return &PolicyCertificateFields{
		PolicyCertificateBase: PolicyCertificateBase{
			PolicyPartBase: PolicyPartBase{
				Version: version,
				Issuer:  issuer,
			},
			RawSubject:      subject,
			RawSerialNumber: serialNumber,
		},
		Domain:             domain,
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		IsIssuer:           isIssuer,
		PublicKey:          publicKey,
		PublicKeyAlgorithm: publicKeyAlgorithm,
		SignatureAlgorithm: signatureAlgorithm,
		TimeStamp:          timeStamp,
		PolicyAttributes:   policyAttributes,
		OwnerSignature:     ownerSignature,
		OwnerPubKeyHash:    ownerPubKeyHash,
	}
}

func (c PolicyCertificateFields) Equal(x PolicyCertificateFields) bool {
	return c.PolicyCertificateBase.Equal(x.PolicyCertificateBase) &&
		c.PublicKeyAlgorithm == x.PublicKeyAlgorithm &&
		bytes.Equal(c.PublicKey, x.PublicKey) &&
		c.Domain == x.Domain &&
		c.NotBefore.Equal(x.NotBefore) &&
		c.NotAfter.Equal(x.NotAfter) &&
		c.SignatureAlgorithm == x.SignatureAlgorithm &&
		c.TimeStamp.Equal(x.TimeStamp) &&
		bytes.Equal(c.OwnerSignature, x.OwnerSignature) &&
		bytes.Equal(c.OwnerPubKeyHash, x.OwnerPubKeyHash) &&
		c.PolicyAttributes.Equal(x.PolicyAttributes)
}

func NewPolicyCertificate(
	version int,
	issuer string,
	subject string,
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
	ownerPubKeyHash []byte,
	issuerSignature []byte,
	issuerPubKeyHash []byte,
	SPTs []SignedPolicyCertificateTimestamp,
) *PolicyCertificate {

	return &PolicyCertificate{
		PolicyCertificateFields: *NewPolicyCertificateFields(
			version,
			issuer,
			subject,
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
			ownerPubKeyHash,
		),
		IssuerSignature:  issuerSignature,
		IssuerPubKeyHash: issuerPubKeyHash,
		SPCTs:            SPTs,
	}
}

func (c PolicyCertificate) Equal(x PolicyCertificate) bool {
	return c.PolicyCertificateFields.Equal(x.PolicyCertificateFields) &&
		bytes.Equal(c.IssuerSignature, x.IssuerSignature) &&
		bytes.Equal(c.IssuerPubKeyHash, x.IssuerPubKeyHash) &&
		equalSlices(c.SPCTs, x.SPCTs)
}

func (s PolicyAttributes) Equal(o PolicyAttributes) bool {
	return true &&
		equalStringSlices(s.TrustedCA, o.TrustedCA) &&
		equalStringSlices(s.AllowedSubdomains, o.AllowedSubdomains)
}

func NewPolicyCertificateRevocationFields(
	version int,
	issuer string,
	subject string,
	serialNumber int,
	timeStamp time.Time,
	ownerSignature []byte,
	ownerPubKeyHash []byte,
) *PolicyCertificateRevocationFields {
	return &PolicyCertificateRevocationFields{
		PolicyCertificateBase: PolicyCertificateBase{
			PolicyPartBase: PolicyPartBase{
				Version: version,
				Issuer:  issuer,
			},
			RawSubject:      subject,
			RawSerialNumber: serialNumber,
		},
		TimeStamp:       timeStamp,
		OwnerSignature:  ownerSignature,
		OwnerPubKeyHash: ownerPubKeyHash,
	}
}

func (c PolicyCertificateRevocationFields) Equal(x PolicyCertificateRevocationFields) bool {
	return c.PolicyCertificateBase.Equal(x.PolicyCertificateBase) &&
		c.TimeStamp == x.TimeStamp &&
		bytes.Equal(c.OwnerSignature, x.OwnerSignature) &&
		bytes.Equal(c.OwnerPubKeyHash, x.OwnerPubKeyHash)
}

func NewPolicyCertificateRevocation(
	version int,
	issuer string,
	subject string,
	serialNumber int,
	timeStamp time.Time,
	ownerSignature []byte,
	ownerPubKeyHash []byte,
	issuerSignature []byte,
	issuerPubKeyHash []byte,
	serverTimestamps []SignedPolicyCertificateRevocationTimestamp,
) *PolicyCertificateRevocation {
	return &PolicyCertificateRevocation{
		PolicyCertificateRevocationFields: *NewPolicyCertificateRevocationFields(
			version,
			issuer,
			subject,
			serialNumber,
			timeStamp,
			ownerSignature,
			ownerPubKeyHash,
		),
		IssuerSignature:  issuerSignature,
		IssuerPubKeyHash: issuerPubKeyHash,
		SPCRTs:           serverTimestamps,
	}
}

func (r PolicyCertificateRevocation) Equal(x PolicyCertificateRevocation) bool {
	return r.PolicyCertificateRevocationFields.Equal(x.PolicyCertificateRevocationFields) &&
		bytes.Equal(r.IssuerSignature, x.IssuerSignature) &&
		bytes.Equal(r.IssuerPubKeyHash, x.IssuerPubKeyHash) &&
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
