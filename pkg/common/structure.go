package common

import (
	"bytes"
	"time"
)

// since I do not use the json, `json:"**",omitempty` can be deleted.
// But I will keep it for now

// root certificate signing request
type RCSR struct {
	Subject            string             `json:"Subject",omitempty`
	Version            int                `json:"Version",omitempty`
	TimeStamp          time.Time          `json:"TimeStamp",omitempty`
	PublicKeyAlgorithm PublicKeyAlgorithm `json:"PublicKeyAlgorithm",omitempty`
	PublicKey          []byte             `json:"PublicKey",omitempty`
	SignatureAlgorithm SignatureAlgorithm `json:"SignatureAlgorithm",omitempty`
	PRCSignature       []byte             `json:"PRCSignature",omitempty`
	Signature          []byte             `json:"Signature",omitempty`
}

// root policy certificate
type RPC struct {
	SerialNumber       int                `json:"SerialNumber",omitempty`
	Subject            string             `json:"Subject",omitempty`
	Version            int                `json:"Version",omitempty`
	PublicKeyAlgorithm PublicKeyAlgorithm `json:"PublicKeyAlgorithm",omitempty`
	PublicKey          []byte             `json:"PublicKey",omitempty`
	NotBefore          time.Time          `json:"NotBefore",omitempty`
	NotAfter           time.Time          `json:"NotAfter",omitempty`
	CAName             string             `json:"CAName",omitempty`
	SignatureAlgorithm SignatureAlgorithm `json:"SignatureAlgorithm",omitempty`
	TimeStamp          time.Time          `json:"TimeStamp",omitempty`
	PRCSignature       []byte             `json:"PRCSignature",omitempty`
	CASignature        []byte             `json:"CASignature",omitempty`
	SPTs               []SPT              `json:"SPT",omitempty`
}

// signed policy timestamp
type SPT struct {
	Version         int       `json:"Version",omitempty`
	Subject         string    `json:"Subject",omitempty`
	CAName          string    `json:"CAName",omitempty`
	LogID           int       `json:"LogID",omitempty`
	CertType        uint8     `json:"CertType",omitempty`
	AddedTS         time.Time `json:"AddedTS",omitempty`
	STH             []byte    `json:"STH",omitempty`
	PoI             [][]byte  `json:"PoI",omitempty`
	STHSerialNumber int       `json:"STHSerialNumber",omitempty`
	Signature       []byte    `json:"Signature",omitempty`
}

// signed policy revocation timestamp
type SPRT struct {
	Version         int       `json:"Version",omitempty`
	Subject         string    `json:"Subject",omitempty`
	CAName          string    `json:"CAName",omitempty`
	LogID           int       `json:"LogID",omitempty`
	CertType        uint8     `json:"CertType",omitempty`
	AddedTS         time.Time `json:"AddedTS",omitempty`
	STH             []byte    `json:"STH",omitempty`
	PoI             [][]byte  `json:"PoI",omitempty`
	STHSerialNumber int       `json:"STHSerialNumber",omitempty`
	Reason          int       `json:"STHSeriReasonalNumber",omitempty`
	Signature       []byte    `json:"Signature",omitempty`
}

//----------------------------------------------------------------
//                       Equal function
//----------------------------------------------------------------
func (rcsr *RCSR) Equal(rcsr_ *RCSR) bool {
	if rcsr.Subject == rcsr_.Subject &&
		rcsr.Version == rcsr_.Version &&
		rcsr.TimeStamp.Equal(rcsr_.TimeStamp) &&
		rcsr.PublicKeyAlgorithm == rcsr_.PublicKeyAlgorithm &&
		bytes.Compare(rcsr.PublicKey, rcsr_.PublicKey) == 0 &&
		rcsr.SignatureAlgorithm == rcsr_.SignatureAlgorithm &&
		bytes.Compare(rcsr.PRCSignature, rcsr_.PRCSignature) == 0 &&
		bytes.Compare(rcsr.Signature, rcsr_.Signature) == 0 {
		return true
	}
	return false
}

func (rpc *RPC) Equal(rpc_ *RPC) bool {
	if rpc.SerialNumber == rpc_.SerialNumber &&
		rpc.Subject == rpc_.Subject &&
		rpc.Version == rpc_.Version &&
		rpc.PublicKeyAlgorithm == rpc_.PublicKeyAlgorithm &&
		bytes.Compare(rpc.PublicKey, rpc_.PublicKey) == 0 &&
		rpc.NotBefore.Equal(rpc_.NotBefore) &&
		rpc.NotAfter.Equal(rpc_.NotAfter) &&
		rpc.CAName == rpc_.CAName &&
		rpc.SignatureAlgorithm == rpc_.SignatureAlgorithm &&
		rpc.TimeStamp.Equal(rpc_.TimeStamp) &&
		bytes.Compare(rpc.PRCSignature, rpc_.PRCSignature) == 0 &&
		bytes.Compare(rpc.CASignature, rpc_.CASignature) == 0 {
		if len(rpc.SPTs) != len(rpc_.SPTs) {
			return false
		}
		for i, v := range rpc.SPTs {
			if !v.Equal(&rpc_.SPTs[i]) {
				return false
			}
		}
		return true
	}
	return false
}

func (spt *SPT) Equal(spt_ *SPT) bool {
	if spt.Version == spt_.Version &&
		spt.Subject == spt_.Subject &&
		spt.CAName == spt_.CAName &&
		spt.LogID == spt_.LogID &&
		spt.CertType == spt_.CertType &&
		spt.AddedTS.Equal(spt_.AddedTS) &&
		bytes.Compare(spt.STH, spt_.STH) == 0 &&
		spt.STHSerialNumber == spt_.STHSerialNumber &&
		bytes.Compare(spt.Signature, spt_.Signature) == 0 {

		if len(spt.PoI) != len(spt_.PoI) {
			return false
		}
		for i, poi := range spt.PoI {
			if bytes.Compare(poi, spt_.PoI[i]) != 0 {
				return false
			}
		}

		return true
	}
	return false
}

func (sprt *SPRT) Equal(sprt_ *SPRT) bool {
	if sprt.Version == sprt_.Version &&
		sprt.Subject == sprt_.Subject &&
		sprt.CAName == sprt_.CAName &&
		sprt.LogID == sprt_.LogID &&
		sprt.CertType == sprt_.CertType &&
		sprt.AddedTS.Equal(sprt_.AddedTS) &&
		bytes.Compare(sprt.STH, sprt_.STH) == 0 &&
		sprt.STHSerialNumber == sprt_.STHSerialNumber &&
		sprt.Reason == sprt_.Reason &&
		bytes.Compare(sprt.Signature, sprt_.Signature) == 0 {
		if len(sprt.PoI) != len(sprt_.PoI) {
			return false
		}
		for i, poi := range sprt.PoI {
			if bytes.Compare(poi, sprt_.PoI[i]) != 0 {
				return false
			}
		}

		return true
	}
	return false
}
