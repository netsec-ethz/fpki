package mapserver

import (
	tire "github.com/netsec-ethz/fpki/pkg/mapserver/tire"
)

func VerifyProofByDomain(proof Proof, domainEntry DomainEntry) (ProofType, bool) {
	if proof.poi.proofType == PoP {
		//TODO(yongzhe): compare h(domainEntry) and proof.poi.proofValue
		value := tire.Hasher(append([]byte(domainEntry.domainName), flattenBytesSlice(domainEntry.certificates)...))
		return PoP, tire.VerifyInclusion(proof.poi.root, proof.poi.proof, tire.Hasher([]byte(proof.domain)), value)
	}

	return PoA, tire.VerifyNonInclusion(proof.poi.root, proof.poi.proof, tire.Hasher([]byte(proof.domain)), proof.poi.proofValue, proof.poi.proofKey)
}
