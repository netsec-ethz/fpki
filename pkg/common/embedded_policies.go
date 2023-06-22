package common

import (
	"bytes"
	"time"
)

type EmbeddedPolicyBase struct {
	PolicyPartBase
}

func (p EmbeddedPolicyBase) Equal(x EmbeddedPolicyBase) bool {
	return p.PolicyPartBase.Equal(x.PolicyPartBase)
}

// . SignedThingTimestamp is common to all timestamps returned by a policy log server.
type SignedThingTimestamp struct {
	EmbeddedPolicyBase
	LogID           []byte    `json:",omitempty"`
	CertType        uint8     `json:",omitempty"`
	AddedTS         time.Time `json:",omitempty"`
	STH             []byte    `json:",omitempty"`
	PoI             []byte    `json:",omitempty"`
	STHSerialNumber int       `json:",omitempty"`
	Signature       []byte    `json:",omitempty"`
}

// SignedPolicyCertificateTimestamp is a signed policy certificate timestamp.
type SignedPolicyCertificateTimestamp struct {
	SignedThingTimestamp
}

// SignedPolicyCertificateRevocationTimestamp is a signed policy certificate revocation timestamp.
type SignedPolicyCertificateRevocationTimestamp struct {
	SignedThingTimestamp
	Reason int `json:",omitempty"`
}

func NewSignedThingTimestamp(
	subject string,
	version int,
	issuer string,
	logID []byte,
	certType uint8,
	addedTS time.Time,
	sTH []byte,
	poI []byte,
	sTHSerialNumber int,
	signature []byte,
) *SignedThingTimestamp {

	return &SignedThingTimestamp{
		EmbeddedPolicyBase: EmbeddedPolicyBase{
			PolicyPartBase: PolicyPartBase{
				Version: version,
				Issuer:  issuer,
			},
		},
		LogID:           logID,
		CertType:        certType,
		AddedTS:         addedTS,
		STH:             sTH,
		PoI:             poI,
		STHSerialNumber: sTHSerialNumber,
		Signature:       signature,
	}
}

func (s SignedThingTimestamp) Equal(x SignedThingTimestamp) bool {
	return s.EmbeddedPolicyBase.Equal(x.EmbeddedPolicyBase) &&
		bytes.Equal(s.LogID, x.LogID) &&
		s.CertType == x.CertType &&
		s.AddedTS.Equal(x.AddedTS) &&
		bytes.Equal(s.STH, x.STH) &&
		bytes.Equal(s.PoI, x.PoI) &&
		s.STHSerialNumber == x.STHSerialNumber &&
		bytes.Equal(s.Signature, x.Signature)
}

func NewSignedPolicyCertificateTimestamp(
	subject string,
	version int,
	issuer string,
	logID []byte,
	certType uint8,
	addedTS time.Time,
	sTH []byte,
	poI []byte,
	sTHSerialNumber int,
	signature []byte,
) *SignedPolicyCertificateTimestamp {
	return &SignedPolicyCertificateTimestamp{
		SignedThingTimestamp: *NewSignedThingTimestamp(
			subject,
			version,
			issuer,
			logID,
			certType,
			addedTS,
			sTH,
			poI,
			sTHSerialNumber,
			signature,
		),
	}
}

func (t SignedPolicyCertificateTimestamp) Equal(x SignedPolicyCertificateTimestamp) bool {
	return t.SignedThingTimestamp.Equal(x.SignedThingTimestamp)
}

func NewSignedPolicyCertificateRevocationTimestamp(
	subject string,
	version int,
	issuer string,
	logID []byte,
	certType uint8,
	addedTS time.Time,
	sTH []byte,
	poI []byte,
	sTHSerialNumber int,
	signature []byte,
	reason int,
) *SignedPolicyCertificateRevocationTimestamp {
	return &SignedPolicyCertificateRevocationTimestamp{
		SignedThingTimestamp: *NewSignedThingTimestamp(
			subject,
			version,
			issuer,
			logID,
			certType,
			addedTS,
			sTH,
			poI,
			sTHSerialNumber,
			signature,
		),
		Reason: reason,
	}
}

func (t SignedPolicyCertificateRevocationTimestamp) Equal(x SignedPolicyCertificateRevocationTimestamp) bool {
	return t.SignedThingTimestamp.Equal(x.SignedThingTimestamp) &&
		t.Reason == x.Reason
}
