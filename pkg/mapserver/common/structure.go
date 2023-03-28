package common

import (
	"encoding/json"
	"fmt"

	"github.com/netsec-ethz/fpki/pkg/common"
)

// DomainEntry: Value of the leaf. The value will be hashed, and stored in the sparse merkle tree
// The design for the v1 version has changed the semantics of this payload. It is computed in DB
// via a stored procedure during ingestion, and retrieved from DB by the responder.
// The domain is identified by the SHA256 of the DomainName in the DB.
type DomainEntry struct {
	DomainName string
	CAEntry    []CAEntry
}

// CAEntry: All certificate, RPC, PC and revocation issued by one specific CA.
// TODO(yongzhe): add PC
type CAEntry struct {
	CAName           string
	CAHash           []byte
	CurrentRPC       common.RPC // TODO(juagargi) we will have a list of RPCs
	FutureRPC        common.RPC //
	CurrentPC        common.SP  // TODO(juagargi) we will have a list of PCs
	Revocation       [][]byte   // TODO(juagargi) these are policy revocations
	FutureRevocation [][]byte   // TODO(juagargi) these are policy revocations
	DomainCerts      [][]byte
	DomainCertChains [][][]byte
}

// SerializedDomainEntry: DomainEntry -> bytes. Use json
func SerializedDomainEntry(domainEntry *DomainEntry) ([]byte, error) {
	result, err := json.Marshal(domainEntry)
	if err != nil {
		return nil, fmt.Errorf("SerializedDomainEntry | Marshal | %w", err)
	}
	return result, nil
}

// DeserializeDomainEntry: bytes -> DomainEntry. Use json
func DeserializeDomainEntry(input []byte) (*DomainEntry, error) {
	result := &DomainEntry{}

	err := json.Unmarshal(input, result)
	if err != nil {
		return nil, fmt.Errorf("DeserializeDomainEntry | Unmarshal | %w", err)
	}
	return result, nil
}

// Proof type enum
// PoA: Proof of Absence; non-inclusion proof
// PoP: Proof of Presence; inclusion proof
type ProofType int

const (
	PoA ProofType = iota
	PoP ProofType = iota
)

// MapServerResponse: response from map server to client
type MapServerResponse struct {
	Domain string
	// serialized bytes of DomainEntry
	DomainEntryBytes []byte `json:"DomainEntryBytes"`
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
