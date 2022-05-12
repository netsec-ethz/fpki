package responder

import (
	"database/sql"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
	"github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
)

// MapResponder: A map responder, which is responsible for receiving client's request. Only read from db.
type MapResponder struct {
	smt *trie.Trie

	// TODO(yongzhe): store this in the db
	storedDomainEntries map[string][]byte
}

// NewMapResponder: return a new MapResponder.
// input:
//   --db: db connection to the tree
//   --root: for a new tree, it can be nil. To load a non-empty tree, root should be the latest root of the tree.
//   --cacheHeight: Maximum height of the cached tree (in memory). 256 means no cache, 0 means cache the whole tree. 0-256
func NewMapResponder(db *sql.DB, root []byte, cacheHeight int) (*MapResponder, error) {
	smt, err := trie.NewTrie(root, trie.Hasher, *db, "cacheStore")
	smt.CacheHeightLimit = cacheHeight
	if err != nil {
		return nil, fmt.Errorf("NewMapResponder | NewTrie | %w", err)
	}

	return &MapResponder{
		smt:                 smt,
		storedDomainEntries: make(map[string][]byte)}, nil
}

// GetMapResponse: Query the proofs and materials for a list of domains. Return type: DomainEntry
func (mapResponder *MapResponder) GetMapResponse(domains []string) ([]common.MapServerResponse, error) {
	// TODO(yongzhe): remove in the final version. For debugging only
	mapResponder.smt.PrintCacheSize()
	proofsResult := []common.MapServerResponse{}

	for _, domain := range domains {
		// hash the domain name -> key
		domainHash := trie.Hasher([]byte(domain))
		// get the merkle proof from the smt. If isPoP == true, then it's a proof of inclusion
		proof, isPoP, proofKey, ProofValue, err := mapResponder.smt.MerkleProof(domainHash)
		if err != nil {
			return nil, fmt.Errorf("GetProofs | MerkleProof | %w", err)
		}

		var proofType common.ProofType
		domainBytes := []byte{}
		switch {
		case isPoP:
			proofType = common.PoP
			var ok bool
			// fetch the domain bytes from map
			// TODO(yongzhe): store the domain bytes in the db
			if domainBytes, ok = mapResponder.storedDomainEntries[domain]; !ok {
				return nil, fmt.Errorf("GetProofs | no such domain: %s, db might be corrupted", domain)
			}
		case !isPoP:
			proofType = common.PoA
		}

		proofsResult = append(proofsResult, common.MapServerResponse{
			Domain: domain,
			PoI: common.PoI{
				Proof:      proof,
				Root:       mapResponder.smt.Root,
				ProofType:  proofType,
				ProofKey:   proofKey,
				ProofValue: ProofValue},
			DomainEntryBytes: domainBytes,
		})
	}
	return proofsResult, nil
}

// ReadDomainEntriesFromDB: Read domain entries from db
// TODO(yongzhe): read data from another table (domainName-material key-value store)
func (mapResponder *MapResponder) ReadDomainEntriesFromDB(domainEntries []common.DomainEntry) error {
	for _, v := range domainEntries {
		domainBytes, err := common.SerialiseDomainEnrty(&v)
		if err != nil {
			return fmt.Errorf("ReadDomainEntriesFromDB | SerialiseDomainEnrty | %w", err)
		}
		mapResponder.storedDomainEntries[v.DomainName] = domainBytes
	}
	return nil
}

// GetRoot: get current root of the smt
func (mapResponder *MapResponder) GetRoot() []byte {
	return mapResponder.smt.Root
}

// Close: close db
func (mapResponder *MapResponder) Close() error {
	return mapResponder.smt.Close()
}
