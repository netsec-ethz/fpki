package prover

import (
	"bytes"
	"encoding/hex"
	"fmt"

	mapCommon "github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
)

// deleteme
func VerifyProofByDomainOld(response mapCommon.MapServerResponse) (mapCommon.ProofType, bool, error) {
	if response.PoI.ProofType == mapCommon.PoP {
		//TODO(yongzhe): compare h(domainEntry) and proof.poi.proofValue
		// value := common.SHA256Hash(response.DomainEntryBytes)
		// return mapCommon.PoP, trie.VerifyInclusion(response.PoI.Root, response.PoI.Proof,
		// 	common.SHA256Hash([]byte(response.Domain)), value), nil

		// The value is the hash of the two payload hashes.
		return mapCommon.PoP, trie.VerifyInclusion(response.PoI.Root, response.PoI.Proof,
			response.DomainEntry.DomainID[:], response.DomainEntry.DomainValue[:]), nil
	}
	return mapCommon.PoA, trie.VerifyNonInclusion(response.PoI.Root, response.PoI.Proof,
		response.DomainEntry.DomainID[:], response.PoI.ProofValue, response.PoI.ProofKey), nil
}

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
