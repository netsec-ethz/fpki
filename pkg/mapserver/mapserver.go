package mapserver

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/netsec-ethz/fpki/pkg/mapserver/batchedsmt"
)

type MapServer struct {
	smt *batchedsmt.SMT
}

func NewMapServer(dburl string, cacheHeight int) (*MapServer, error) {
	db, err := sql.Open("mysql", dburl)
	if err != nil {
		return nil, fmt.Errorf("NewMapServer | sql.Open | %w", err)
	}

	smt, err := batchedsmt.NewSMT(nil, batchedsmt.Hasher, db)
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

	err = mapServer.smt.StoreUpdatedNode()
	if err != nil {
		return fmt.Errorf("UpdateDomains | StoreUpdatedNode | %w", err)
	}
	return nil
}

func (mapServer *MapServer) GetProofs(domains []string) ([]Proof, error) {
	proofsResult := []Proof{}

	for _, domain := range domains {
		hashV := batchedsmt.Hasher([]byte(domain))
		start := time.Now()
		proof, err := mapServer.smt.MerkleProof(hashV)
		end := time.Now()
		fmt.Println(end.Sub(start))
		if err != nil {
			return nil, fmt.Errorf("GetProofs | MerkleProof | %w", err)
		}
		proofsResult = append(proofsResult, Proof{domain: domain, poi: PoI{proof: proof, root: mapServer.smt.Root}})
	}

	return proofsResult, nil
}
