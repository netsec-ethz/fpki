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
	DomainName  string
	DomainID    *common.SHA256Output // This is the SHA256 of the domain name
	DomainValue *common.SHA256Output // = SHA256 ( certsPayloadID || polsPayloadID )

	// TODO(juagargi) remove the CertsIDsID and PolicyIDsID from here and from the DB.

	CertIDsID   *common.SHA256Output
	CertIDs     []byte // Includes x509 leafs and trust chains, raw ASN.1 DER.
	PolicyIDsID *common.SHA256Output
	PolicyIDs   []byte // Includes RPCs, SPs, etc. JSON.
}

// DeletemeSerializeDomainEntry uses json to serialize.
func DeletemeSerializeDomainEntry(domainEntry *DomainEntry) ([]byte, error) {
	result, err := json.Marshal(domainEntry)
	if err != nil {
		return nil, fmt.Errorf("SerializedDomainEntry | Marshal | %w", err)
	}
	return result, nil
}

// DeletemeDeserializeDomainEntry converts json into a DomainEntry.
func DeletemeDeserializeDomainEntry(input []byte) (*DomainEntry, error) {
	result := &DomainEntry{}
	err := json.Unmarshal(input, result)
	if err != nil {
		return nil, fmt.Errorf("DeserializeDomainEntry | Unmarshal | %w", err)
	}
	return result, nil
}
