package common

import (
	"bytes"
	"time"
)

// MarshallableObject is an object that can be marshalled and unmarshalled to and from JSON.
type MarshallableObject interface {
	Raw() []byte // Returns the Raw JSON this object was unmarshaled from (nil if none).
}

// PolicyDocument is an interface that is implemented by all objects that are part of the set
// of "policy objects". A policy object is that one that represents functionality of policies
// for a domain, such as RPC, RCSR, SPT, SPRT, SP, PSR or Policy.
type PolicyDocument interface {
	MarshallableObject
	Subject() string
}

type PolicyObjectBase struct {
	RawJSON    []byte `json:"-"` // omit from JSON (un)marshaling
	RawSubject string `json:"Subject,omitempty"`
}

func (o PolicyObjectBase) Raw() []byte     { return o.RawJSON }
func (o PolicyObjectBase) Subject() string { return o.RawSubject }

// root certificate signing request

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

// Policy is a domain policy.
type Policy struct {
	TrustedCA         []string `json:",omitempty"`
	AllowedSubdomains []string `json:",omitempty"`
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
