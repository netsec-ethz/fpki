package common

import (
	"bytes"
	"time"
)

// RCSR is a root certificate signing request.
type RCSR struct {
	PolicyObjectBase
	Version            int                `json:",omitempty"`
	TimeStamp          time.Time          `json:",omitempty"`
	PublicKeyAlgorithm PublicKeyAlgorithm `json:",omitempty"`
	PublicKey          []byte             `json:",omitempty"`
	SignatureAlgorithm SignatureAlgorithm `json:",omitempty"`
	PRCSignature       []byte             `json:",omitempty"`
	Signature          []byte             `json:",omitempty"`
}

// PSR is a Policy Signing Request.
type PSR struct {
	SubjectRaw        string       `json:",omitempty"`
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
		PolicyObjectBase: PolicyObjectBase{
			RawSubject: Subject,
		},
		Version:            Version,
		TimeStamp:          TimeStamp,
		PublicKeyAlgorithm: PublicKeyAlgo,
		PublicKey:          PublicKey,
		SignatureAlgorithm: SignatureAlgo,
		PRCSignature:       PRCSignature,
		Signature:          Signature,
	}
}

func (rcsr *RCSR) Equal(rcsr_ *RCSR) bool {
	return true &&
		rcsr.RawSubject == rcsr_.RawSubject &&
		rcsr.Version == rcsr_.Version &&
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
		SubjectRaw:        Subject,
		Policy:            Policy,
		TimeStamp:         TimeStamp,
		RootCertSignature: RootCertSignature,
	}
}
