package common

import "github.com/netsec-ethz/fpki/pkg/common"

// Proof type enum
// PoA: Proof of Absence; non-inclusion proof
// PoP: Proof of Presence; inclusion proof
type ProofType int

const (
	PoA ProofType = iota
	PoP
)

// MapServerResponse: response from map server to client
type MapServerResponse struct {
	Domain string
	// serialized bytes of DomainEntry
	DomainEntryBytes []byte `json:"DomainEntryBytes"`
	DomainEntryID    *common.SHA256Output
	PoI              PoI
	TreeHeadSig      []byte
}

// PoI: Proof of Inclusion(or non-inclusion)
type PoI struct {
	ProofType  ProofType
	Proof      [][]byte
	Root       []byte
	ProofKey   []byte
	ProofValue []byte
}
