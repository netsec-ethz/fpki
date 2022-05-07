package mapserver

import (
	"github.com/netsec-ethz/fpki/pkg/mapserver/batchedsmt"
)

func VerifyProofByDomain(proof Proof, domainEntry DomainEntry) bool {
	value := batchedsmt.Hasher(append([]byte(domainEntry.domainName), flattenBytesSlice(domainEntry.certificates)...))
	return batchedsmt.VerifyMerkleProof(proof.poi.root, proof.poi.proof, batchedsmt.Hasher([]byte(proof.domain)), value)
}
