package common

import (
	"encoding/json"
	"fmt"

	"github.com/netsec-ethz/fpki/pkg/common"
)

// DomainEntry: Value of the leaf. The value will be hashed, and stored in the sparse merkle tree
type DomainEntry struct {
	DomainName string
	CAEntry    []CAEntry
}

// CAEntry: All certificate, RPC, PC and revocation issued by one specific CA.
// TODO(yongzhe): add PC
type CAEntry struct {
	CAName           string
	CAHash           []byte
	CurrentRPC       common.RPC
	FutureRPC        common.RPC
	CurrentPC        common.PC
	Revocation       [][]byte
	FutureRevocation [][]byte
	DomainCerts      [][]byte
}

// SerialiseDomainEntry: DomainEntry -> bytes. Use json
func SerialiseDomainEntry(domainEntry *DomainEntry) ([]byte, error) {
	result, err := json.Marshal(domainEntry)
	if err != nil {
		return nil, fmt.Errorf("SerialiseDomainEnrty | Marshal | %w", err)
	}
	return result, nil
}

// DesrialiseDomainEntry: bytes -> DomainEntry. Use json
func DesrialiseDomainEntry(input []byte) (*DomainEntry, error) {
	result := &DomainEntry{}

	err := json.Unmarshal(input, result)
	if err != nil {
		return nil, fmt.Errorf("DesrialiseDomainEnrty | Unmarshal | %w", err)
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
	// serialised bytes of DomainEntry
	DomainEntryBytes []byte
	PoI              PoI
}

// PoI: Proof of Inclusion(or non-inclusion)
type PoI struct {
	ProofType  ProofType
	Proof      [][]byte
	Root       []byte
	ProofKey   []byte
	ProofValue []byte
}
