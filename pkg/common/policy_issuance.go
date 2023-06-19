package common

import (
	"bytes"
	"time"
)

type PolicyIssuer interface {
	PolicyPart
	Subject() string
}

type PolicyIssuerBase struct {
	PolicyPartBase
	RawSubject string `json:"Subject,omitempty"`
}

func (c PolicyIssuerBase) Subject() string { return c.RawSubject }
func (c PolicyIssuerBase) Equal(x PolicyIssuerBase) bool {
	return c.PolicyPartBase.Equal(x.PolicyPartBase) &&
		c.RawSubject == x.RawSubject
}

// RCSR is a root certificate signing request.
type RCSR struct {
	PolicyIssuerBase
	TimeStamp          time.Time          `json:",omitempty"`
	PublicKeyAlgorithm PublicKeyAlgorithm `json:",omitempty"`
	PublicKey          []byte             `json:",omitempty"`
	SignatureAlgorithm SignatureAlgorithm `json:",omitempty"`
	PRCSignature       []byte             `json:",omitempty"`
	Signature          []byte             `json:",omitempty"`
}

// PSR is a Policy Signing Request.
type PSR struct {
	PolicyIssuerBase
	Policy            DomainPolicy `json:",omitempty"`
	TimeStamp         time.Time    `json:",omitempty"`
	RootCertSignature []byte       `json:",omitempty"`
}

func NewRCSR(
	Subject string,
	Version int,
	TimeStamp time.Time,
	PublicKeyAlgo PublicKeyAlgorithm,
	PublicKey []byte,
	SignatureAlgo SignatureAlgorithm,
	PRCSignature []byte,
	Signature []byte,
) *RCSR {

	return &RCSR{
		PolicyIssuerBase: PolicyIssuerBase{
			PolicyPartBase: PolicyPartBase{
				Version: Version,
			},
			RawSubject: Subject,
		},
		TimeStamp:          TimeStamp,
		PublicKeyAlgorithm: PublicKeyAlgo,
		PublicKey:          PublicKey,
		SignatureAlgorithm: SignatureAlgo,
		PRCSignature:       PRCSignature,
		Signature:          Signature,
	}
}

func (rcsr *RCSR) Equal(rcsr_ *RCSR) bool {
	return rcsr.PolicyIssuerBase.Equal(rcsr.PolicyIssuerBase) &&
		rcsr.TimeStamp.Equal(rcsr_.TimeStamp) &&
		rcsr.PublicKeyAlgorithm == rcsr_.PublicKeyAlgorithm &&
		bytes.Equal(rcsr.PublicKey, rcsr_.PublicKey) &&
		rcsr.SignatureAlgorithm == rcsr_.SignatureAlgorithm &&
		bytes.Equal(rcsr.PRCSignature, rcsr_.PRCSignature) &&
		bytes.Equal(rcsr.Signature, rcsr_.Signature)
}

func NewPSR(
	Subject string,
	Policy DomainPolicy,
	TimeStamp time.Time,
	RootCertSignature []byte,
) *PSR {

	return &PSR{
		PolicyIssuerBase: PolicyIssuerBase{
			RawSubject: Subject,
		},
		Policy:            Policy,
		TimeStamp:         TimeStamp,
		RootCertSignature: RootCertSignature,
	}
}
