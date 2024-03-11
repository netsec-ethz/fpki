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

func (o SignedPolicyCertificateTimestamp) Raw() ([]byte, error) {
	return rawTemplate(o)
}

// SignedPolicyCertificateRevocationTimestamp is a signed policy certificate revocation timestamp.
type SignedPolicyCertificateRevocationTimestamp struct {
	SignedEntryTimestamp
}

func (o SignedPolicyCertificateRevocationTimestamp) Raw() ([]byte, error) {
	return rawTemplate(o)
}

func NewSignedEntryTimestamp(
	version int,
	logID []byte,
	addedTS time.Time,
	signature []byte,
) *SignedEntryTimestamp {

	return &SignedEntryTimestamp{
		EmbeddedPolicyBase: EmbeddedPolicyBase{
			PolicyPartBase: PolicyPartBase{
				Version: version,
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

type SignedEntryTimestampSignatureInput struct {
	SignedEntryTimestamp
	Entry []byte
}

func NewSignedEntryTimestampSignatureInput(
	entry []byte,
	spct *SignedPolicyCertificateTimestamp,
) *SignedEntryTimestampSignatureInput {

	return &SignedEntryTimestampSignatureInput{
		SignedEntryTimestamp: *NewSignedEntryTimestamp(
			spct.Version,
			spct.LogID,
			spct.AddedTS,
			spct.Signature,
		),
		Entry: entry,
	}
}

func (t SignedEntryTimestampSignatureInput) Equal(x SignedEntryTimestampSignatureInput) bool {
	return t.SignedEntryTimestamp.Equal(x.SignedEntryTimestamp) &&
		bytes.Equal(t.Entry, x.Entry)
}

func NewSignedPolicyCertificateTimestamp(
	version int,
	logID []byte,
	addedTS time.Time,
	signature []byte,
) *SignedPolicyCertificateTimestamp {
	return &SignedPolicyCertificateTimestamp{
		SignedEntryTimestamp: *NewSignedEntryTimestamp(
			version,
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
	logID []byte,
	addedTS time.Time,
	signature []byte,
) *SignedPolicyCertificateRevocationTimestamp {
	return &SignedPolicyCertificateRevocationTimestamp{
		SignedEntryTimestamp: *NewSignedEntryTimestamp(
			version,
			logID,
			addedTS,
			signature,
		),
	}
}

func (t SignedPolicyCertificateRevocationTimestamp) Equal(x SignedPolicyCertificateRevocationTimestamp) bool {
	return t.SignedEntryTimestamp.Equal(x.SignedEntryTimestamp)
}
