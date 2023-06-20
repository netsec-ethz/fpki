package common

import (
	"bytes"
	"time"
)

// PolicyCertificate is any policy document that can be exchanged among mapservers, CT log servers,
// and others.
type PolicyCertificate interface {
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

// RPC is a Root Policy Certificate.
type RPC struct {
	PolicyCertificateBase
	IsCA               bool               `json:",omitempty"`
	PublicKeyAlgorithm PublicKeyAlgorithm `json:",omitempty"`
	PublicKey          []byte             `json:",omitempty"`
	NotBefore          time.Time          `json:",omitempty"`
	NotAfter           time.Time          `json:",omitempty"`
	SignatureAlgorithm SignatureAlgorithm `json:",omitempty"`
	TimeStamp          time.Time          `json:",omitempty"`
	PRCSignature       []byte             `json:",omitempty"`
	CASignature        []byte             `json:",omitempty"`
	SPTs               []SPT              `json:",omitempty"`
}

// SP is a Signed Policy.
type SP struct {
	PolicyCertificateBase
	Policies          DomainPolicy `json:",omitempty"`
	TimeStamp         time.Time    `json:",omitempty"`
	CASignature       []byte       `json:",omitempty"`
	RootCertSignature []byte       `json:",omitempty"`
	SPTs              []SPT        `json:",omitempty"`
}

// DomainPolicy is a domain policy that specifies what is or not acceptable for a domain.
type DomainPolicy struct {
	TrustedCA         []string `json:",omitempty"`
	AllowedSubdomains []string `json:",omitempty"`
}

// PCRevocation is for now empty.
type PCRevocation struct {
	PolicyCertificateBase
	// TODO(juagargi) define the revocation.
}

func NewRPC(
	Subject string,
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
) *RPC {

	return &RPC{
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

func (rpc RPC) Equal(x RPC) bool {
	return rpc.PolicyCertificateBase.Equal(x.PolicyCertificateBase) &&
		rpc.PublicKeyAlgorithm == x.PublicKeyAlgorithm &&
		bytes.Equal(rpc.PublicKey, x.PublicKey) &&
		rpc.NotBefore.Equal(x.NotBefore) &&
		rpc.NotAfter.Equal(x.NotAfter) &&
		rpc.SignatureAlgorithm == x.SignatureAlgorithm &&
		rpc.TimeStamp.Equal(x.TimeStamp) &&
		bytes.Equal(rpc.PRCSignature, x.PRCSignature) &&
		bytes.Equal(rpc.CASignature, x.CASignature) &&
		equalSPTs(rpc.SPTs, x.SPTs)
}

func NewSP(
	Subject string,
	Policy DomainPolicy,
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

func (s SP) Equal(o SP) bool {
	return s.PolicyCertificateBase.Equal(o.PolicyCertificateBase) &&
		s.TimeStamp.Equal(o.TimeStamp) &&
		bytes.Equal(s.CASignature, o.CASignature) &&
		bytes.Equal(s.RootCertSignature, o.RootCertSignature) &&
		s.Policies.Equal(o.Policies) &&
		equalSPTs(s.SPTs, o.SPTs)
}

func (s DomainPolicy) Equal(o DomainPolicy) bool {
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

func equalSPTs(a, b []SPT) bool {
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
