package prover

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/netsec-ethz/fpki/pkg/common"
	mapCommon "github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
)

// deleteme
func VerifyProofByDomainOld(proof mapCommon.MapServerResponse) (mapCommon.ProofType, bool, error) {
	if proof.PoI.ProofType == mapCommon.PoP {
		//TODO(yongzhe): compare h(domainEntry) and proof.poi.proofValue
		value := common.SHA256Hash(proof.DomainEntryBytes)
		return mapCommon.PoP, trie.VerifyInclusion(proof.PoI.Root, proof.PoI.Proof,
			common.SHA256Hash([]byte(proof.Domain)), value), nil
	}
	return mapCommon.PoA, trie.VerifyNonInclusion(proof.PoI.Root, proof.PoI.Proof,
		common.SHA256Hash([]byte(proof.Domain)), proof.PoI.ProofValue, proof.PoI.ProofKey), nil
}

// VerifyProofByDomain verifies the MapServerResponse (received from map server),
// and returns the type of proof, and proofing result.
func VerifyProofByDomain(proof *mapCommon.MapServerResponse) (mapCommon.ProofType, bool, error) {
	if proof.PoI.ProofType == mapCommon.PoP {
		if !bytes.Equal(proof.DomainEntryID[:], proof.PoI.ProofValue) {
			return 0, false, fmt.Errorf("different hash for value %s != %s",
				hex.EncodeToString(proof.DomainEntryID[:]),
				hex.EncodeToString(proof.PoI.ProofValue))
		}
		return mapCommon.PoP, trie.VerifyInclusion(proof.PoI.Root, proof.PoI.Proof,
			common.SHA256Hash([]byte(proof.Domain)), proof.DomainEntryID[:]), nil
	}
	return mapCommon.PoA, trie.VerifyNonInclusion(proof.PoI.Root, proof.PoI.Proof,
		common.SHA256Hash([]byte(proof.Domain)), proof.PoI.ProofValue, proof.PoI.ProofKey), nil
}
