package prover

import (
	"github.com/netsec-ethz/fpki/pkg/mapserver/common"
	tire "github.com/netsec-ethz/fpki/pkg/mapserver/tire"
)

// VerifyProofByDomain: verify the MapServerResponse(received from map server)
func VerifyProofByDomain(proof common.MapServerResponse) (common.ProofType, bool, error) {
	if proof.PoI.ProofType == common.PoP {
		//TODO(yongzhe): compare h(domainEntry) and proof.poi.proofValue
		value := tire.Hasher(proof.DomainEntryBytes)
		return common.PoP, tire.VerifyInclusion(proof.PoI.Root, proof.PoI.Proof, tire.Hasher([]byte(proof.Domain)), value), nil
	}
	return common.PoA, tire.VerifyNonInclusion(proof.PoI.Root, proof.PoI.Proof, tire.Hasher([]byte(proof.Domain)), proof.PoI.ProofValue, proof.PoI.ProofKey), nil
}
