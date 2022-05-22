package responder

import (
	"database/sql"
	"encoding/hex"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/domain"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
)

// MapResponder: A map responder, which is responsible for receiving client's request. Only read from db.
type MapResponder struct {
	smt *trie.Trie

	dbConn *sql.DB
}

// NewMapResponder: return a new MapResponder.
// input:
//   --db: db connection to the tree
//   --root: for a new tree, it can be nil. To load a non-empty tree, root should be the latest root of the tree.
//   --cacheHeight: Maximum height of the cached tree (in memory). 256 means no cache, 0 means cache the whole tree. 0-256
func NewMapResponder(db db.Conn, root []byte, cacheHeight int, initTable bool) (*MapResponder, error) {
	smt, err := trie.NewTrie(root, trie.Hasher, db)
	smt.CacheHeightLimit = cacheHeight
	if err != nil {
		return nil, fmt.Errorf("NewMapResponder | NewTrie | %w", err)
	}

	dbConn, err := sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/map?maxAllowedPacket=1073741824")
	if err != nil {
		return nil, fmt.Errorf("NewMapResponder | sql.Open | %w", err)
	}

	return &MapResponder{
		smt:    smt,
		dbConn: dbConn,
	}, nil
}

// GetMapResponse: Query the proofs and materials for a list of domains. Return type: MapServerResponse
func (mapResponder *MapResponder) GetDomainProof(domainName string) ([]common.MapServerResponse, error) {
	proofsResult := []common.MapServerResponse{}
	domainList, err := parseDomainName(domainName)
	if err != nil {
		return nil, fmt.Errorf("GetDomainProof | parseDomainName | %w", err)
	}

	for _, domain := range domainList {
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

			// fetch the domain bytes from map
			var domainContent string
			err := mapResponder.dbConn.QueryRow("SELECT `value` FROM map.domainEntries WHERE `key`='" + hex.EncodeToString(domainHash) + "';").Scan(&domainContent)
			if err != nil {
				return nil, fmt.Errorf("GetDomainProof | QueryRow | %w", err)
			}
			domainBytes = []byte(domainContent)
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

// parseDomainName: get the parent domain until E2LD, return a list of domains(remove the www. and *.)
// eg: video.google.com -> video.google.com google.com
// eg: *.google.com -> google.com
// eg: www.google.com -> google.com
func parseDomainName(domainName string) ([]string, error) {
	result, err := domain.SplitE2LD(domainName)
	resultString := []string{}
	var domain string
	if err != nil {
		return nil, fmt.Errorf("parseDomainName | SplitE2LD | %w", err)
	} else if len(result) == 0 {
		return nil, fmt.Errorf("domain length is zero")
	}
	domain = result[len(result)-1]
	resultString = append(resultString, domain)
	for i := len(result) - 2; i >= 0; i-- {
		domain = result[i] + "." + domain
		resultString = append(resultString, domain)
	}
	return resultString, nil
}

// GetRoot: get current root of the smt
func (mapResponder *MapResponder) GetRoot() []byte {
	return mapResponder.smt.Root
}

// Close: close db
func (mapResponder *MapResponder) Close() error {
	return mapResponder.smt.Close()
}
