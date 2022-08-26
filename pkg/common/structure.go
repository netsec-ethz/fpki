package common

import (
	"bytes"
	"time"
)

// root certificate signing request
type RCSR struct {
	Subject            string             `json:",omitempty"`
	Version            int                `json:",omitempty"`
	TimeStamp          time.Time          `json:",omitempty"`
	PublicKeyAlgorithm PublicKeyAlgorithm `json:",omitempty"`
	PublicKey          []byte             `json:",omitempty"`
	SignatureAlgorithm SignatureAlgorithm `json:",omitempty"`
	PRCSignature       []byte             `json:",omitempty"`
	Signature          []byte             `json:",omitempty"`
}

// root policy certificate
type RPC struct {
	SerialNumber       int                `json:",omitempty"`
	Subject            string             `json:",omitempty"`
	Version            int                `json:",omitempty"`
	PublicKeyAlgorithm PublicKeyAlgorithm `json:",omitempty"`
	PublicKey          []byte             `json:",omitempty"`
	NotBefore          time.Time          `json:",omitempty"`
	NotAfter           time.Time          `json:",omitempty"`
	CAName             string             `json:",omitempty"`
	SignatureAlgorithm SignatureAlgorithm `json:",omitempty"`
	TimeStamp          time.Time          `json:",omitempty"`
	PRCSignature       []byte             `json:",omitempty"`
	CASignature        []byte             `json:",omitempty"`
	SPTs               []SPT              `json:",omitempty"`
}

// signed policy timestamp
type SPT struct {
	Version         int       `json:",omitempty"`
	Subject         string    `json:",omitempty"`
	CAName          string    `json:",omitempty"`
	LogID           int       `json:",omitempty"`
	CertType        uint8     `json:",omitempty"`
	AddedTS         time.Time `json:",omitempty"`
	STH             []byte    `json:",omitempty"`
	PoI             [][]byte  `json:",omitempty"`
	STHSerialNumber int       `json:",omitempty"`
	Signature       []byte    `json:",omitempty"`
}

// signed policy revocation timestamp
type SPRT struct {
	Version         int       `json:",omitempty"`
	Subject         string    `json:",omitempty"`
	CAName          string    `json:",omitempty"`
	LogID           int       `json:",omitempty"`
	CertType        uint8     `json:",omitempty"`
	AddedTS         time.Time `json:",omitempty"`
	STH             []byte    `json:",omitempty"`
	PoI             [][]byte  `json:",omitempty"`
	STHSerialNumber int       `json:",omitempty"`
	Reason          int       `json:",omitempty"`
	Signature       []byte    `json:",omitempty"`
}

// Signed Policy
type SP struct {
	Policies          Policy    `json:",omitempty"`
	TimeStamp         time.Time `json:",omitempty"`
	Subject           string    `json:",omitempty"`
	CAName            string    `json:",omitempty"`
	SerialNumber      int       `json:",omitempty"`
	CASignature       []byte    `json:",omitempty"`
	RootCertSignature []byte    `json:",omitempty"`
	SPTs              []SPT     `json:",omitempty"`
}

// Policy Signing Request
type PSR struct {
	Policies          Policy    `json:",omitempty"`
	TimeStamp         time.Time `json:",omitempty"`
	DomainName        string    `json:",omitempty"`
	RootCertSignature []byte    `json:",omitempty"`
}

// Domain policy
type Policy struct {
	TrustedCA []string
}

//----------------------------------------------------------------
//                       Equal function
//----------------------------------------------------------------

// listed funcs are Equal() func for each structure
func (rcsr *RCSR) Equal(rcsr_ *RCSR) bool {
	return rcsr.Subject == rcsr_.Subject &&
		rcsr.Version == rcsr_.Version &&
		rcsr.TimeStamp.Equal(rcsr_.TimeStamp) &&
		rcsr.PublicKeyAlgorithm == rcsr_.PublicKeyAlgorithm &&
		bytes.Compare(rcsr.PublicKey, rcsr_.PublicKey) == 0 &&
		rcsr.SignatureAlgorithm == rcsr_.SignatureAlgorithm &&
		bytes.Compare(rcsr.PRCSignature, rcsr_.PRCSignature) == 0 &&
		bytes.Compare(rcsr.Signature, rcsr_.Signature) == 0
}

func (s SPT) Equal(o SPT) bool {
	return s.Version == o.Version && s.Subject == o.Subject && s.CAName == o.CAName &&
		s.LogID == o.LogID && s.CertType == o.CertType && s.AddedTS.Equal(o.AddedTS) &&
		bytes.Equal(s.STH, o.STH) && equalSliceSlicesBytes(s.PoI, o.PoI) &&
		s.STHSerialNumber == o.STHSerialNumber && bytes.Equal(s.Signature, o.Signature)
}

func (s Policy) Equal(o Policy) bool {
	for i, v := range s.TrustedCA {
		if v != o.TrustedCA[i] {
			return false
		}
	}
	return true
}

func (s SP) Equal(o SP) bool {
	if s.TimeStamp.Equal(o.TimeStamp) &&
		s.Subject == o.Subject &&
		s.CAName == o.CAName &&
		s.SerialNumber == o.SerialNumber &&
		bytes.Equal(s.CASignature, o.CASignature) &&
		bytes.Equal(s.RootCertSignature, o.RootCertSignature) &&
		s.Policies.Equal(o.Policies) {
		for i, v := range s.SPTs {
			if !v.Equal(o.SPTs[i]) {
				return false
			}
		}
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
			if !v.Equal(rpc_.SPTs[i]) {
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

func equalSliceSlicesBytes(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}
