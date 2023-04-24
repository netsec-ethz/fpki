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
	DomainID   []byte // This is the SHA256 of the domain name

	RPCs        []common.RPC
	PCs         []common.SP
	Revocations []common.PCRevocation
	DomainCerts []byte // Includes leafs and trust chain certificates, raw x509 DER.1.
}

// SerializeDomainEntry uses json to serialize.
func SerializeDomainEntry(domainEntry *DomainEntry) ([]byte, error) {
	result, err := json.Marshal(domainEntry)
	if err != nil {
		return nil, fmt.Errorf("SerializedDomainEntry | Marshal | %w", err)
	}
	return result, nil
}

// DeserializeDomainEntry converts json into a DomainEntry.
func DeserializeDomainEntry(input []byte) (*DomainEntry, error) {
	result := &DomainEntry{}
	err := json.Unmarshal(input, result)
	if err != nil {
		return nil, fmt.Errorf("DeserializeDomainEntry | Unmarshal | %w", err)
	}
	return result, nil
}
