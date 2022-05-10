package responder

import (
	"database/sql"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
	"github.com/netsec-ethz/fpki/pkg/mapserver/common"
	tire "github.com/netsec-ethz/fpki/pkg/mapserver/tire"
)

type MapResponder struct {
	smt *tire.Trie
}

func NewMapResponder(db *sql.DB, root []byte, cacheHeight int) (*MapResponder, error) {
	smt, err := tire.NewTrie(root, tire.Hasher, *db)
	smt.CacheHeightLimit = cacheHeight
	if err != nil {
		return nil, fmt.Errorf("NewMapServer | NewSMT | %w", err)
	}

	return &MapResponder{smt: smt}, nil
}

func (mapResponder *MapResponder) GetProofs(domains []string) ([]common.Proof, error) {
	mapResponder.smt.PrintCacheSize()
	proofsResult := []common.Proof{}

	for _, domain := range domains {
		domainHash := tire.Hasher([]byte(domain))
		proof, isPoP, proofKey, ProofValue, err := mapResponder.smt.MerkleProof(domainHash)
		if err != nil {
			return nil, fmt.Errorf("GetProofs | MerkleProof | %w", err)
		}

		var proofType common.ProofType
		switch {
		case isPoP:
			proofType = common.PoP
		case !isPoP:
			proofType = common.PoA
		}

		proofsResult = append(proofsResult, common.Proof{Domain: domain,
			PoI: common.PoI{
				Proof:      proof,
				Root:       mapResponder.smt.Root,
				ProofType:  proofType,
				ProofKey:   proofKey,
				ProofValue: ProofValue}})
	}

	return proofsResult, nil
}

func (mapResponder *MapResponder) GetRoot() []byte {
	return mapResponder.smt.Root
}

func (mapResponder *MapResponder) Close() error {
	return mapResponder.smt.Close()
}
