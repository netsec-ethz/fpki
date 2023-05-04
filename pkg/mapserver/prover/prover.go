package prover

import (
	"bytes"
	"encoding/hex"
	"fmt"

	mapCommon "github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
)

// VerifyProofByDomain verifies the MapServerResponse (received from map server),
// and returns the type of proof, and proofing result.
func VerifyProofByDomain(response *mapCommon.MapServerResponse) (mapCommon.ProofType, bool, error) {
	if response.PoI.ProofType == mapCommon.PoP {
		if !bytes.Equal(response.DomainEntry.DomainValue[:], response.PoI.ProofValue) {
			return 0, false, fmt.Errorf("different hash for value %s != %s",
				hex.EncodeToString(response.DomainEntry.DomainID[:]),
				hex.EncodeToString(response.PoI.ProofValue))
		}
		return mapCommon.PoP, trie.VerifyInclusion(response.PoI.Root, response.PoI.Proof,
			response.DomainEntry.DomainID[:], response.DomainEntry.DomainValue[:]), nil
	}
	return mapCommon.PoA, trie.VerifyNonInclusion(response.PoI.Root, response.PoI.Proof,
		response.DomainEntry.DomainID[:], response.PoI.ProofValue, response.PoI.ProofKey), nil
}
