package responder

import (
	"context"
	"fmt"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/domain"
	mapCommon "github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
)

// responderWorker: worker
type responderWorker struct {
	dbConn          db.Conn
	smt             *trie.Trie
	clientInputChan chan ClientRequest
	domainParser    *domain.DomainParser
}

// work for worker
func (responderWorker *responderWorker) work() {
	for {
		newRequest := <-responderWorker.clientInputChan

		proofs, err := responderWorker.getDomainProof(newRequest.ctx, newRequest.domainName)
		if err != nil {
			newRequest.resultChan <- ClientResponse{Err: err}
			continue
		}
		newRequest.resultChan <- ClientResponse{Proof: proofs}
	}
}

// getDomainProof: generate proof for one client
func (responderWorker *responderWorker) getDomainProof(ctx context.Context, domainName string) ([]mapCommon.MapServerResponse, error) {
	proofsResult := []mapCommon.MapServerResponse{}

	// check domain name first
	domainList, err := responderWorker.domainParser.ParseDomainName(domainName)
	if err != nil {
		if err == domain.InvalidDomainNameErr {
			return nil, err
		}
		return nil, fmt.Errorf("GetDomainProof | parseDomainName | %w", err)
	}

	for _, domain := range domainList {
		domainHash := common.SHA256Hash32Bytes([]byte(domain))

		merkleStart := time.Now()
		proof, isPoP, proofKey, ProofValue, err := responderWorker.smt.MerkleProof(ctx, domainHash[:])
		if err != nil {
			return nil, fmt.Errorf("getDomainProof | MerkleProof | %w", err)
		}
		merkleEnd := time.Now()
		fmt.Println("merkle: ", merkleEnd.Sub(merkleStart))

		var proofType mapCommon.ProofType
		domainBytes := []byte{}
		// If it is PoP, query the domain entry. If it is PoA, directly return the PoA
		switch {
		case isPoP:
			proofType = mapCommon.PoP
			dbStart := time.Now()
			result, err := responderWorker.dbConn.RetrieveOneKeyValuePairDomainEntries(ctx, domainHash)
			if err != nil {
				return nil, fmt.Errorf("GetDomainProof | RetrieveOneKeyValuePairDomainEntries | %w", err)
			}
			dbEnd := time.Now()
			fmt.Println("db: ", dbEnd.Sub(dbStart), " domain size: ", len(result.Value))

			domainBytes = result.Value
		case !isPoP:
			proofType = mapCommon.PoA
		}

		proofsResult = append(proofsResult, mapCommon.MapServerResponse{
			Domain: domain,
			PoI: mapCommon.PoI{
				Proof:      proof,
				Root:       responderWorker.smt.Root,
				ProofType:  proofType,
				ProofKey:   proofKey,
				ProofValue: ProofValue},
			DomainEntryBytes: domainBytes,
		})
	}

	return proofsResult, nil
}
