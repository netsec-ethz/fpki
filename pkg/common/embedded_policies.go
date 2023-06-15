package common

import (
	"bytes"
	"time"
)

// SPT is a signed policy timestamp.
type SPT struct {
	PolicyObjectBase
	Version         int       `json:",omitempty"`
	CAName          string    `json:",omitempty"`
	LogID           int       `json:",omitempty"`
	CertType        uint8     `json:",omitempty"`
	AddedTS         time.Time `json:",omitempty"`
	STH             []byte    `json:",omitempty"`
	PoI             []byte    `json:",omitempty"`
	STHSerialNumber int       `json:",omitempty"`
	Signature       []byte    `json:",omitempty"`
}

func NewSPT(
	Subject string,
	Version int,
	CAName string,
	LogID int,
	CertType uint8,
	AddedTS time.Time,
	STH []byte,
	PoI []byte,
	STHSerialNumber int,
	Signature []byte,
) *SPT {

	return &SPT{
		PolicyObjectBase: PolicyObjectBase{
			RawSubject: Subject,
		},
		Version:         Version,
		CAName:          CAName,
		LogID:           LogID,
		CertType:        CertType,
		AddedTS:         AddedTS,
		STH:             STH,
		PoI:             PoI,
		STHSerialNumber: STHSerialNumber,
		Signature:       Signature,
	}
}

// SPRT is a signed policy revocation timestamp.
type SPRT struct {
	SPT
	Reason int `json:",omitempty"`
}

func NewSPRT(SPT *SPT, Reason int) *SPRT {
	return &SPRT{
		SPT:    *SPT,
		Reason: Reason,
	}
}

func (s SPT) Equal(o SPT) bool {
	return true &&
		s.Version == o.Version &&
		s.RawSubject == o.RawSubject &&
		s.CAName == o.CAName &&
		s.LogID == o.LogID &&
		s.CertType == o.CertType &&
		s.AddedTS.Equal(o.AddedTS) &&
		bytes.Equal(s.STH, o.STH) &&
		bytes.Equal(s.PoI, o.PoI) &&
		s.STHSerialNumber == o.STHSerialNumber &&
		bytes.Equal(s.Signature, o.Signature)
}

func (sprt *SPRT) Equal(sprt_ *SPRT) bool {
	return sprt.SPT.Equal(sprt_.SPT) &&
		sprt.Reason == sprt_.Reason
}
