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

// PolicyCertificate is a Root Policy Certificate.
type PolicyCertificate struct {
	PolicyCertificateBase
	IsIssuer           bool               `json:",omitempty"`
	PublicKeyAlgorithm PublicKeyAlgorithm `json:",omitempty"`
	PublicKey          []byte             `json:",omitempty"`
	NotBefore          time.Time          `json:",omitempty"`
	NotAfter           time.Time          `json:",omitempty"`
	SignatureAlgorithm SignatureAlgorithm `json:",omitempty"`
	TimeStamp          time.Time          `json:",omitempty"`
	PRCSignature       []byte             `json:",omitempty"`
	CASignature        []byte             `json:",omitempty"`
	PolicyAttributes   []PolicyAttributes `json:",omitempty"`
	SPTs               []SPT              `json:",omitempty"`
}

// SP is a Signed Policy.
type SP struct {
	PolicyCertificateBase
	Policies          PolicyAttributes `json:",omitempty"`
	TimeStamp         time.Time        `json:",omitempty"`
	CASignature       []byte           `json:",omitempty"`
	RootCertSignature []byte           `json:",omitempty"`
	SPTs              []SPT            `json:",omitempty"`
}

// PolicyAttributes is a domain policy that specifies what is or not acceptable for a domain.
type PolicyAttributes struct {
	TrustedCA         []string `json:",omitempty"`
	AllowedSubdomains []string `json:",omitempty"`
}

// PCRevocation is for now empty.
type PCRevocation struct {
	PolicyCertificateBase
	// TODO(juagargi) define the revocation.
}

func NewPolicyCertificate(
	Subject string,
	policyAttributes []PolicyAttributes,
	serialNumber int,
	Version int,
	PublicKeyAlgorithm PublicKeyAlgorithm,
	PublicKey []byte,
	NotBefore time.Time,
	NotAfter time.Time,
	issuer string,
	SignatureAlgorithm SignatureAlgorithm,
	TimeStamp time.Time,
	PRCSignature []byte,
	CASignature []byte,
	SPTs []SPT,
) *PolicyCertificate {

	return &PolicyCertificate{
		PolicyCertificateBase: PolicyCertificateBase{
			PolicyPartBase: PolicyPartBase{
				Version: Version,
				Issuer:  issuer,
			},
			RawSubject:      Subject,
			RawSerialNumber: serialNumber,
		},
		PublicKeyAlgorithm: PublicKeyAlgorithm,
		PublicKey:          PublicKey,
		NotBefore:          NotBefore,
		NotAfter:           NotAfter,
		SignatureAlgorithm: SignatureAlgorithm,
		TimeStamp:          TimeStamp,
		PRCSignature:       PRCSignature,
		CASignature:        CASignature,
		SPTs:               SPTs,
	}
}

func NewSP(
	Subject string,
	Policy PolicyAttributes,
	TimeStamp time.Time,
	issuer string,
	serialNumber int,
	CASignature []byte,
	RootCertSignature []byte,
	SPTs []SPT,
) *SP {

	return &SP{
		PolicyCertificateBase: PolicyCertificateBase{
			PolicyPartBase: PolicyPartBase{
				Issuer: issuer,
			},
			RawSubject:      Subject,
			RawSerialNumber: serialNumber,
		},
		Policies:          Policy,
		TimeStamp:         TimeStamp,
		CASignature:       CASignature,
		RootCertSignature: RootCertSignature,
		SPTs:              SPTs,
	}
}

func (c PolicyCertificate) Equal(x PolicyCertificate) bool {
	return c.PolicyCertificateBase.Equal(x.PolicyCertificateBase) &&
		c.PublicKeyAlgorithm == x.PublicKeyAlgorithm &&
		bytes.Equal(c.PublicKey, x.PublicKey) &&
		c.NotBefore.Equal(x.NotBefore) &&
		c.NotAfter.Equal(x.NotAfter) &&
		c.SignatureAlgorithm == x.SignatureAlgorithm &&
		c.TimeStamp.Equal(x.TimeStamp) &&
		bytes.Equal(c.PRCSignature, x.PRCSignature) &&
		bytes.Equal(c.CASignature, x.CASignature) &&
		equalSlices(c.SPTs, x.SPTs) &&
		equalSlices(c.PolicyAttributes, x.PolicyAttributes)
}

func (s SP) Equal(o SP) bool {
	return s.PolicyCertificateBase.Equal(o.PolicyCertificateBase) &&
		s.TimeStamp.Equal(o.TimeStamp) &&
		bytes.Equal(s.CASignature, o.CASignature) &&
		bytes.Equal(s.RootCertSignature, o.RootCertSignature) &&
		s.Policies.Equal(o.Policies) &&
		equalSlices(s.SPTs, o.SPTs)
}

func (s PolicyAttributes) Equal(o PolicyAttributes) bool {
	return true &&
		equalStringSlices(s.TrustedCA, o.TrustedCA) &&
		equalStringSlices(s.AllowedSubdomains, o.AllowedSubdomains)
}

func NewPCRevocation(subject string) *PCRevocation {
	return &PCRevocation{
		PolicyCertificateBase: PolicyCertificateBase{
			RawSubject: subject,
		},
	}
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
