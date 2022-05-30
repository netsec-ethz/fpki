package responder

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/domain"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
)

// MapResponder: A map responder, which is responsible for receiving client's request. Only read from db.
type MapResponder struct {
	smt *trie.Trie

	dbConn db.Conn
}

// NewMapResponder: return a new MapResponder.
// input:
//   --db: db connection to the tree
//   --root: for a new tree, it can be nil. To load a non-empty tree, root should be the latest root of the tree.
//   --cacheHeight: Maximum height of the cached tree (in memory). 256 means no cache, 0 means cache the whole tree. 0-256
func NewMapResponder(root []byte, cacheHeight int) (*MapResponder, error) {
	dbConn, err := db.Connect_old()
	if err != nil {
		return nil, fmt.Errorf("NewMapResponder | Connect_old | %w", err)
	}
	smt, err := trie.NewTrie(root, trie.Hasher, dbConn)
	if err != nil {
		return nil, fmt.Errorf("NewMapResponder | NewTrie | %w", err)
	}
	smt.CacheHeightLimit = cacheHeight

	smt.LoadCache(root)

	return &MapResponder{
		smt:    smt,
		dbConn: dbConn,
	}, nil
}

// GetMapResponse: Query the proofs and materials for a list of domains. Return type: MapServerResponse
func (mapResponder *MapResponder) GetDomainProof(ctx context.Context, domainName string) ([]common.MapServerResponse, error) {

	start := time.Now()
	proofsResult := []common.MapServerResponse{}
	domainList, err := parseDomainName(domainName)
	if err != nil {
		return nil, fmt.Errorf("GetDomainProof | parseDomainName | %w", err)
	}

	// var for benchmark
	// TODO(yongzhe): delete this later
	var merStart time.Time
	var merEnd time.Time
	var newStart time.Time
	var newEnd time.Time
	var hashStart time.Time
	var hashEnd time.Time
	var hexStart time.Time
	var hexEnd time.Time

	durationList := []time.Duration{}

	for _, domain := range domainList {
		// hash the domain name -> key
		hashStart = time.Now()
		domainHash := trie.Hasher([]byte(domain))
		hashEnd = time.Now()
		durationList = append(durationList, hashEnd.Sub(hashStart))

		// get the merkle proof from the smt. If isPoP == true, then it's a proof of inclusion
		merStart = time.Now()
		proof, isPoP, proofKey, ProofValue, err := mapResponder.smt.MerkleProof(domainHash)
		if err != nil {
			return nil, fmt.Errorf("GetProofs | MerkleProof | %w", err)
		}
		merEnd = time.Now()
		if merEnd.Sub(merStart) > time.Millisecond {
			fmt.Println("fetch proof: ", merEnd.Sub(merStart))
		}

		durationList = append(durationList, merEnd.Sub(merStart))

		newStart = time.Now()
		var proofType common.ProofType
		domainBytes := []byte{}
		// If it is PoP, query the domain entry. If it is PoA, directly return the PoA
		switch {
		case isPoP:
			proofType = common.PoP
			hexStart = time.Now()
			domainHashString := hex.EncodeToString(domainHash)
			hexEnd = time.Now()
			fmt.Println("hex time:", hexEnd.Sub(hexStart))
			result, err := mapResponder.dbConn.RetrieveOneKeyValuePair(ctx, domainHashString, db.DomainEntries)
			if err != nil {
				return nil, fmt.Errorf("GetDomainProof | QueryRow | %w", err)
			}
			domainBytes = result.Value
		case !isPoP:
			proofType = common.PoA
		}
		newEnd = time.Now()

		durationList = append(durationList, newEnd.Sub(newStart))

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
	end := time.Now()
	// print the slow query
	if end.Sub(start) > time.Millisecond {
		fmt.Println("time to fetch: ", end.Sub(start))
		fmt.Println(domainName)
		for i, timeST := range durationList {
			fmt.Println(timeST)
			if i%3 == 2 {
				fmt.Println()
			}
		}
		fmt.Println("--------------------------------------")
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
