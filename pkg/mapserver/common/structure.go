package common

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
	// TODO(juagargi) change the DomainEntry to something less verbose, to reduce the bytes transmitted to the client.
	DomainEntry *DomainEntry
	PoI         PoI
	TreeHeadSig []byte
}

// PoI: Proof of Inclusion(or non-inclusion)
type PoI struct {
	ProofType  ProofType
	Proof      [][]byte
	Root       []byte
	ProofKey   []byte
	ProofValue []byte
}
