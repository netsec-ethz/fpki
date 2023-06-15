package common

import (
	"bytes"
	"time"
)

// PolicyObject is an interface that is implemented by all objects that are part of the set
// of "policy objects". A policy object is that one that represents functionality of policies
// for a domain, such as RPC, RCSR, SPT, SPRT, SP, PSR or Policy.
type PolicyObject interface {
	Raw() []byte
	Subject() string
}

type PolicyObjectBase struct {
	RawJSON    []byte `json:"-"` // omit from JSON (un)marshaling
	RawSubject string `json:"Subject,omitempty"`
}

func (o PolicyObjectBase) Raw() []byte     { return o.RawJSON }
func (o PolicyObjectBase) Subject() string { return o.RawSubject }

// root certificate signing request
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

// root policy certificate
type RPC struct {
	PolicyObjectBase
	SerialNumber       int                `json:",omitempty"`
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

func NewRPC(
	Subject string,
	SerialNumber int,
	Version int,
	PublicKeyAlgorithm PublicKeyAlgorithm,
	PublicKey []byte,
	NotBefore time.Time,
	NotAfter time.Time,
	CAName string,
	SignatureAlgorithm SignatureAlgorithm,
	TimeStamp time.Time,
	PRCSignature []byte,
	CASignature []byte,
	SPTs []SPT,
) *RPC {

	return &RPC{
		PolicyObjectBase: PolicyObjectBase{
			RawSubject: Subject,
		},
		SerialNumber:       SerialNumber,
		Version:            Version,
		PublicKeyAlgorithm: PublicKeyAlgorithm,
		PublicKey:          PublicKey,
		NotBefore:          NotBefore,
		NotAfter:           NotAfter,
		CAName:             CAName,
		SignatureAlgorithm: SignatureAlgorithm,
		TimeStamp:          TimeStamp,
		PRCSignature:       PRCSignature,
		CASignature:        CASignature,
		SPTs:               SPTs,
	}
}

// PCRevocation is for now empty.
type PCRevocation struct {
	PolicyObjectBase
	// TODO(juagargi) define the revocation.
}

func NewPCRevocation(subject string) *PCRevocation {
	return &PCRevocation{
		PolicyObjectBase{
			RawSubject: subject,
		},
	}
}

// signed policy timestamp
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

// signed policy revocation timestamp
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

// Signed Policy
type SP struct {
	PolicyObjectBase
	Policies          Policy    `json:",omitempty"`
	TimeStamp         time.Time `json:",omitempty"`
	CAName            string    `json:",omitempty"`
	SerialNumber      int       `json:",omitempty"`
	CASignature       []byte    `json:",omitempty"`
	RootCertSignature []byte    `json:",omitempty"`
	SPTs              []SPT     `json:",omitempty"`
}

func NewSP(
	Subject string,
	Policies Policy,
	TimeStamp time.Time,
	CAName string,
	SerialNumber int,
	CASignature []byte,
	RootCertSignature []byte,
	SPTs []SPT,
) *SP {

	return &SP{
		PolicyObjectBase: PolicyObjectBase{
			RawSubject: Subject,
		},
		Policies:          Policies,
		TimeStamp:         TimeStamp,
		CAName:            CAName,
		SerialNumber:      SerialNumber,
		CASignature:       CASignature,
		RootCertSignature: RootCertSignature,
		SPTs:              SPTs,
	}
}

// Policy Signing Request
type PSR struct {
	SubjectRaw        string    `json:",omitempty"`
	Policy            Policy    `json:",omitempty"`
	TimeStamp         time.Time `json:",omitempty"`
	RootCertSignature []byte    `json:",omitempty"`
}

func NewPSR(
	Subject string,
	Policy Policy,
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
		rcsr.RawSubject == rcsr_.RawSubject &&
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
		s.RawSubject == o.RawSubject &&
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
		rpc.RawSubject == rpc_.RawSubject &&
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
	return sprt.SPT.Equal(sprt_.SPT) &&
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
