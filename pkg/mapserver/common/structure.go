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
	CurrentRPC       common.RPC
	FutureRPC        common.RPC
	Revocation       [][]byte
	FutureRevocation [][]byte
	DomainCerts      [][]byte
}

/*
// SerialiseDomainEnrty: DomainEntry -> bytes. Use gob
func SerialiseDomainEnrty(domainEntry *DomainEntry) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(*domainEntry); err != nil {
		return nil, fmt.Errorf("SerialiseDomainEnrty | Encode | %w", err)
	}
	return buf.Bytes(), nil
}

// DesrialiseDomainEnrty: bytes -> DomainEntry. Use gob
func DesrialiseDomainEnrty(input []byte) (*DomainEntry, error) {
	buf := bytes.NewBuffer(input)
	dec := gob.NewDecoder(buf)

	result := &DomainEntry{}
	if err := dec.Decode(result); err != nil {
		return nil, fmt.Errorf("DesrialiseDomainEnrty | Decode | %w", err)
	}
	return result, nil
}
*/

// SerialiseDomainEnrty: DomainEntry -> bytes. Use json
func SerialiseDomainEnrty(domainEntry *DomainEntry) ([]byte, error) {
	result, err := json.Marshal(domainEntry)
	if err != nil {
		return nil, fmt.Errorf("SerialiseDomainEnrty | Marshal | %w", err)
	}
	return result, nil
}

// DesrialiseDomainEnrty: bytes -> DomainEntry. Use json
func DesrialiseDomainEnrty(input []byte) (*DomainEntry, error) {
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
