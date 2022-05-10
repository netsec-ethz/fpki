package prover

import (
	"fmt"

	"github.com/netsec-ethz/fpki/pkg/mapserver/common"
	tire "github.com/netsec-ethz/fpki/pkg/mapserver/tire"
)

func VerifyProofByDomain(proof common.Proof, domainEntry common.DomainEntry) (common.ProofType, bool, error) {
	if proof.PoI.ProofType == common.PoP {
		domainEntryBytes, err := common.SerialiseDomainEnrty(&domainEntry)
		if err != nil {
			return common.PoA, false, fmt.Errorf("VerifyProofByDomain | SerialiseDomainEnrty | %w", err)
		}
		//TODO(yongzhe): compare h(domainEntry) and proof.poi.proofValue
		value := tire.Hasher(domainEntryBytes)
		return common.PoP, tire.VerifyInclusion(proof.PoI.Root, proof.PoI.Proof, tire.Hasher([]byte(proof.Domain)), value), nil
	}

	return common.PoA, tire.VerifyNonInclusion(proof.PoI.Root, proof.PoI.Proof, tire.Hasher([]byte(proof.Domain)), proof.PoI.ProofValue, proof.PoI.ProofKey), nil
}
