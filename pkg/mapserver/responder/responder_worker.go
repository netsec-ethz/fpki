package responder

import (
	"context"
	"fmt"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/domain"
	mapCommon "github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
)

type responderWorker struct {
	dbConn          db.Conn
	smt             *trie.Trie
	clientInputChan chan ClientRequest
	domainParser    *domain.DomainParser
}

func (responderWorker *responderWorker) work() {
	for {
		newRequest := <-responderWorker.clientInputChan

		proofs, err := responderWorker.getDomainProof(newRequest.ctx, newRequest.domainName)
		if err != nil {
			newRequest.resultChan <- ClientResponse{Err: err}
		}
		newRequest.resultChan <- ClientResponse{Proof: proofs}
	}
}

func (responderWorker *responderWorker) getDomainProof(ctx context.Context, domainName string) ([]mapCommon.MapServerResponse, error) {
	//start := time.Now()
	proofsResult := []mapCommon.MapServerResponse{}
	domainList, err := responderWorker.domainParser.ParseDomainName(domainName)
	if err != nil {
		return nil, fmt.Errorf("GetDomainProof | parseDomainName | %w", err)
	}

	// var for benchmark
	// TODO(yongzhe): delete this later
	/*
		var merStart time.Time
		var merEnd time.Time
		var newStart time.Time
		var newEnd time.Time
		var hashStart time.Time
		var hashEnd time.Time
		var dbReadTime []time.Duration
		var resultSize []int
	*/

	//durationList := []time.Duration{}

	for _, domain := range domainList {
		// hash the domain name -> key
		//hashStart = time.Now()
		domainHash := common.SHA256Hash32Bytes([]byte(domain))
		//hashEnd = time.Now()
		//durationList = append(durationList, hashEnd.Sub(hashStart))

		// get the merkle proof from the smt. If isPoP == true, then it's a proof of inclusion
		//merStart = time.Now()
		proof, isPoP, proofKey, ProofValue, err := responderWorker.smt.MerkleProof(domainHash[:])
		if err != nil {
			return nil, fmt.Errorf("GetProofs | MerkleProof | %w", err)
		}
		//merEnd = time.Now()
		//if merEnd.Sub(merStart) > time.Millisecond {
		//	fmt.Println("fetch proof: ", merEnd.Sub(merStart))
		//}

		//durationList = append(durationList, merEnd.Sub(merStart))

		//newStart = time.Now()
		var proofType mapCommon.ProofType
		domainBytes := []byte{}
		// If it is PoP, query the domain entry. If it is PoA, directly return the PoA
		switch {
		case isPoP:
			proofType = mapCommon.PoP
			//dbStart := time.Now()
			result, err := responderWorker.dbConn.RetrieveOneKeyValuePairDomainEntries(ctx, domainHash)
			if err != nil {
				return nil, fmt.Errorf("GetDomainProof | QueryRow | %w", err)
			}
			//dbEnd := time.Now()
			//fmt.Println(dbEnd.Sub(dbStart))
			//dbReadTime = append(dbReadTime, dbEnd.Sub(dbStart))
			//resultSize = append(resultSize, len(result.Value))
			domainBytes = result.Value

		case !isPoP:
			proofType = mapCommon.PoA
		}
		//newEnd = time.Now()

		//durationList = append(durationList, newEnd.Sub(newStart))

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
	//end := time.Now()
	// print the slow query
	/*
		if end.Sub(start) > time.Millisecond {
			fmt.Println("time to fetch: ", end.Sub(start))
			fmt.Println(domainName)
			for i, timeST := range durationList {
				fmt.Println(timeST)
				if i%3 == 2 {
					fmt.Println()
				}
			}
			fmt.Println("db read time")
			for _, dbTime := range dbReadTime {
				fmt.Println(dbTime)
			}

			for _, domain := range domainList {
				fmt.Println("key", hex.EncodeToString(trie.Hasher([]byte(domain))))
			}

			for _, resultSize := range resultSize {
				fmt.Println("size: ", resultSize)
			}

			fmt.Println("--------------------------------------")
		}
	*/

	return proofsResult, nil
}
