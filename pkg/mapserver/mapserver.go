package mapserver

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"
	tire "github.com/netsec-ethz/fpki/pkg/mapserver/tire"
)

type MapServer struct {
	smt *tire.Trie
}

func NewMapServer(dburl string, cacheHeight int) (*MapServer, error) {
	db, err := sql.Open("mysql", dburl)
	if err != nil {
		return nil, fmt.Errorf("NewMapServer | sql.Open | %w", err)
	}

	smt, err := tire.NewTrie(nil, tire.Hasher, *db)
	smt.CacheHeightLimit = cacheHeight
	if err != nil {
		return nil, fmt.Errorf("NewMapServer | NewSMT | %w", err)
	}

	return &MapServer{smt: smt}, nil
}

func (mapServer *MapServer) UpdateDomains(domainEntries []DomainEntry) error {
	keyValuePair := HashDomainEntriesThenSort(domainEntries)

	keys := [][]byte{}
	values := [][]byte{}

	for _, v := range keyValuePair {
		keys = append(keys, v.key)
		values = append(values, v.value)
	}

	_, err := mapServer.smt.Update(keys, values)
	if err != nil {
		return fmt.Errorf("UpdateDomains | Update | %w", err)
	}

	err = mapServer.smt.Commit()
	if err != nil {
		return fmt.Errorf("UpdateDomains | StoreUpdatedNode | %w", err)
	}
	return nil
}

func (mapServer *MapServer) GetProofs(domains []string) ([]Proof, error) {
	proofsResult := []Proof{}

	for _, domain := range domains {
		hashV := tire.Hasher([]byte(domain))
		start := time.Now()
		proof, isPoP, proofKey, ProofValue, err := mapServer.smt.MerkleProof(hashV)
		end := time.Now()
		fmt.Println(end.Sub(start))
		if err != nil {
			return nil, fmt.Errorf("GetProofs | MerkleProof | %w", err)
		}
		var proofType ProofType
		switch {
		case isPoP:
			proofType = PoP
		case !isPoP:
			proofType = PoA
		}
		proofsResult = append(proofsResult, Proof{domain: domain,
			poi: PoI{
				proof:      proof,
				root:       mapServer.smt.Root,
				proofType:  proofType,
				proofKey:   proofKey,
				proofValue: ProofValue}})
	}

	return proofsResult, nil
}
