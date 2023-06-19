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

// SPT is a signed policy timestamp.
type SPT struct {
	EmbeddedPolicyBase
	LogID           int       `json:",omitempty"`
	CertType        uint8     `json:",omitempty"`
	AddedTS         time.Time `json:",omitempty"`
	STH             []byte    `json:",omitempty"`
	PoI             []byte    `json:",omitempty"`
	STHSerialNumber int       `json:",omitempty"`
	Signature       []byte    `json:",omitempty"`
}

// SPRT is a signed policy revocation timestamp.
type SPRT struct {
	SPT
	Reason int `json:",omitempty"`
}

func NewSPT(
	Subject string,
	Version int,
	issuer string,
	LogID int,
	CertType uint8,
	AddedTS time.Time,
	STH []byte,
	PoI []byte,
	STHSerialNumber int,
	Signature []byte,
) *SPT {

	return &SPT{
		EmbeddedPolicyBase: EmbeddedPolicyBase{
			PolicyPartBase: PolicyPartBase{
				Version: Version,
				Issuer:  issuer,
			},
		},
		LogID:           LogID,
		CertType:        CertType,
		AddedTS:         AddedTS,
		STH:             STH,
		PoI:             PoI,
		STHSerialNumber: STHSerialNumber,
		Signature:       Signature,
	}
}

func (s SPT) Equal(x SPT) bool {
	return s.EmbeddedPolicyBase.Equal(x.EmbeddedPolicyBase) &&
		s.LogID == x.LogID &&
		s.CertType == x.CertType &&
		s.AddedTS.Equal(x.AddedTS) &&
		bytes.Equal(s.STH, x.STH) &&
		bytes.Equal(s.PoI, x.PoI) &&
		s.STHSerialNumber == x.STHSerialNumber &&
		bytes.Equal(s.Signature, x.Signature)
}

func NewSPRT(SPT *SPT, Reason int) *SPRT {
	return &SPRT{
		SPT:    *SPT,
		Reason: Reason,
	}
}

func (sprt SPRT) Equal(x SPRT) bool {
	return sprt.SPT.Equal(x.SPT) &&
		sprt.Reason == x.Reason
}
