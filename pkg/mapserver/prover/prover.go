package prover

import (
	"github.com/netsec-ethz/fpki/pkg/common"
	mapCommon "github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
)

// VerifyProofByDomain: verify the MapServerResponse(received from map server), return the type of proof, and proofing result
func VerifyProofByDomain(proof mapCommon.MapServerResponse) (mapCommon.ProofType, bool, error) {
	if proof.PoI.ProofType == mapCommon.PoP {
		//TODO(yongzhe): compare h(domainEntry) and proof.poi.proofValue
		value := common.SHA256Hash(proof.DomainEntryBytes)
		return mapCommon.PoP, trie.VerifyInclusion(proof.PoI.Root, proof.PoI.Proof, common.SHA256Hash([]byte(proof.Domain)), value), nil
	}
	return mapCommon.PoA, trie.VerifyNonInclusion(proof.PoI.Root, proof.PoI.Proof, common.SHA256Hash([]byte(proof.Domain)), proof.PoI.ProofValue, proof.PoI.ProofKey), nil
}
