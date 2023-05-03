package common

import (
	"bytes"
	"time"
)

// PolicyObject is an interface that is implemented by all objects that are part of the set
// of "policy objects". A policy object is that one that represents functionality of policies
// for a domain, such as RPC, RCSR, SPT, SPRT, SP, PSR or Policy.
type PolicyObject interface {
	__PolicyObjectMarkerMethod()
}

type PolicyObjectBase struct {
	RawJSON []byte `json:"-"` // omit from JSON (un)marshaling
}

func (PolicyObjectBase) __PolicyObjectMarkerMethod() {}

// root certificate signing request
type RCSR struct {
	PolicyObjectBase
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
	PolicyObjectBase
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

// PCRevocation is for now empty.
type PCRevocation struct {
	PolicyObjectBase
	// TODO(juagargi) define the revocation.
}

// signed policy timestamp
type SPT struct {
	PolicyObjectBase
	Version         int       `json:",omitempty"`
	Subject         string    `json:",omitempty"`
	CAName          string    `json:",omitempty"`
	LogID           int       `json:",omitempty"`
	CertType        uint8     `json:",omitempty"`
	AddedTS         time.Time `json:",omitempty"`
	STH             []byte    `json:",omitempty"`
	PoI             []byte    `json:",omitempty"`
	STHSerialNumber int       `json:",omitempty"`
	Signature       []byte    `json:",omitempty"`
}

// signed policy revocation timestamp
type SPRT struct {
	SPT
	Reason int `json:",omitempty"`
}

// Signed Policy
type SP struct {
	PolicyObjectBase
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
	PolicyObjectBase
	Policies          Policy    `json:",omitempty"`
	TimeStamp         time.Time `json:",omitempty"`
	DomainName        string    `json:",omitempty"`
	RootCertSignature []byte    `json:",omitempty"`
}

// Domain policy
type Policy struct {
	TrustedCA         []string `json:",omitempty"`
	AllowedSubdomains []string `json:",omitempty"`
}

//----------------------------------------------------------------
//                       Equal function
//----------------------------------------------------------------

// listed funcs are Equal() func for each structure
func (rcsr *RCSR) Equal(rcsr_ *RCSR) bool {
	return true &&
		rcsr.Subject == rcsr_.Subject &&
		rcsr.Version == rcsr_.Version &&
		rcsr.TimeStamp.Equal(rcsr_.TimeStamp) &&
		rcsr.PublicKeyAlgorithm == rcsr_.PublicKeyAlgorithm &&
		bytes.Equal(rcsr.PublicKey, rcsr_.PublicKey) &&
		rcsr.SignatureAlgorithm == rcsr_.SignatureAlgorithm &&
		bytes.Equal(rcsr.PRCSignature, rcsr_.PRCSignature) &&
		bytes.Equal(rcsr.Signature, rcsr_.Signature)
}

func (s SPT) Equal(o SPT) bool {
	return true &&
		s.Version == o.Version &&
		s.Subject == o.Subject &&
		s.CAName == o.CAName &&
		s.LogID == o.LogID &&
		s.CertType == o.CertType &&
		s.AddedTS.Equal(o.AddedTS) &&
		bytes.Equal(s.STH, o.STH) &&
		bytes.Equal(s.PoI, o.PoI) &&
		s.STHSerialNumber == o.STHSerialNumber &&
		bytes.Equal(s.Signature, o.Signature)
}

func (s Policy) Equal(o Policy) bool {
	if len(s.TrustedCA) != len(o.TrustedCA) {
		return false
	}
	for i, v := range s.TrustedCA {
		if v != o.TrustedCA[i] {
			return false
		}
	}
	return true
}

func (s SP) Equal(o SP) bool {
	return true &&
		s.TimeStamp.Equal(o.TimeStamp) &&
		s.Subject == o.Subject &&
		s.CAName == o.CAName &&
		s.SerialNumber == o.SerialNumber &&
		bytes.Equal(s.CASignature, o.CASignature) &&
		bytes.Equal(s.RootCertSignature, o.RootCertSignature) &&
		s.Policies.Equal(o.Policies) &&
		equalSPTs(s.SPTs, o.SPTs)
}

func (rpc *RPC) Equal(rpc_ *RPC) bool {
	return true &&
		rpc.SerialNumber == rpc_.SerialNumber &&
		rpc.Subject == rpc_.Subject &&
		rpc.Version == rpc_.Version &&
		rpc.PublicKeyAlgorithm == rpc_.PublicKeyAlgorithm &&
		bytes.Equal(rpc.PublicKey, rpc_.PublicKey) &&
		rpc.NotBefore.Equal(rpc_.NotBefore) &&
		rpc.NotAfter.Equal(rpc_.NotAfter) &&
		rpc.CAName == rpc_.CAName &&
		rpc.SignatureAlgorithm == rpc_.SignatureAlgorithm &&
		rpc.TimeStamp.Equal(rpc_.TimeStamp) &&
		bytes.Equal(rpc.PRCSignature, rpc_.PRCSignature) &&
		bytes.Equal(rpc.CASignature, rpc_.CASignature) &&
		equalSPTs(rpc.SPTs, rpc_.SPTs)
}

func (sprt *SPRT) Equal(sprt_ *SPRT) bool {
	return true &&
		sprt.SPT.Equal(sprt_.SPT) &&
		sprt.Reason == sprt_.Reason
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
