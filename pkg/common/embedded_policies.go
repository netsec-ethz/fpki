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

// SignedEntryTimestamp is common to all timestamps returned by a policy log server.
type SignedEntryTimestamp struct {
	EmbeddedPolicyBase
	LogID     []byte    `json:",omitempty"` // SHA256 of public key of CT log server.
	AddedTS   time.Time `json:",omitempty"` // When it was added to the CT log server.
	Signature []byte    `json:",omitempty"` // Using public key of CT log server.
}

// SignedPolicyCertificateTimestamp is a signed policy certificate timestamp.
type SignedPolicyCertificateTimestamp struct {
	SignedEntryTimestamp
}

// SignedPolicyCertificateRevocationTimestamp is a signed policy certificate revocation timestamp.
type SignedPolicyCertificateRevocationTimestamp struct {
	SignedEntryTimestamp
	Reason int `json:",omitempty"`
}

func NewSignedEntryTimestamp(
	version int,
	issuer string,
	logID []byte,
	addedTS time.Time,
	signature []byte,
) *SignedEntryTimestamp {

	return &SignedEntryTimestamp{
		EmbeddedPolicyBase: EmbeddedPolicyBase{
			PolicyPartBase: PolicyPartBase{
				Version: version,
				Issuer:  issuer,
			},
		},
		LogID:     logID,
		AddedTS:   addedTS,
		Signature: signature,
	}
}

func (s SignedEntryTimestamp) Equal(x SignedEntryTimestamp) bool {
	return s.EmbeddedPolicyBase.Equal(x.EmbeddedPolicyBase) &&
		bytes.Equal(s.LogID, x.LogID) &&
		s.AddedTS.Equal(x.AddedTS) &&
		bytes.Equal(s.Signature, x.Signature)
}

func NewSignedPolicyCertificateTimestamp(
	version int,
	issuer string,
	logID []byte,
	addedTS time.Time,
	signature []byte,
) *SignedPolicyCertificateTimestamp {
	return &SignedPolicyCertificateTimestamp{
		SignedEntryTimestamp: *NewSignedEntryTimestamp(
			version,
			issuer,
			logID,
			addedTS,
			signature,
		),
	}
}

func (t SignedPolicyCertificateTimestamp) Equal(x SignedPolicyCertificateTimestamp) bool {
	return t.SignedEntryTimestamp.Equal(x.SignedEntryTimestamp)
}

func NewSignedPolicyCertificateRevocationTimestamp(
	version int,
	issuer string,
	logID []byte,
	addedTS time.Time,
	signature []byte,
	reason int,
) *SignedPolicyCertificateRevocationTimestamp {
	return &SignedPolicyCertificateRevocationTimestamp{
		SignedEntryTimestamp: *NewSignedEntryTimestamp(
			version,
			issuer,
			logID,
			addedTS,
			signature,
		),
		Reason: reason,
	}
}

func (t SignedPolicyCertificateRevocationTimestamp) Equal(x SignedPolicyCertificateRevocationTimestamp) bool {
	return t.SignedEntryTimestamp.Equal(x.SignedEntryTimestamp) &&
		t.Reason == x.Reason
}
