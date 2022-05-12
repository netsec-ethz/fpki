package prover

import (
	"github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
)

// VerifyProofByDomain: verify the MapServerResponse(received from map server)
func VerifyProofByDomain(proof common.MapServerResponse) (common.ProofType, bool, error) {
	if proof.PoI.ProofType == common.PoP {
		//TODO(yongzhe): compare h(domainEntry) and proof.poi.proofValue
		value := trie.Hasher(proof.DomainEntryBytes)
		return common.PoP, trie.VerifyInclusion(proof.PoI.Root, proof.PoI.Proof, trie.Hasher([]byte(proof.Domain)), value), nil
	}
	return common.PoA, trie.VerifyNonInclusion(proof.PoI.Root, proof.PoI.Proof, trie.Hasher([]byte(proof.Domain)), proof.PoI.ProofValue, proof.PoI.ProofKey), nil
}
