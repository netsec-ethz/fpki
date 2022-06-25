package responder

import (
	"context"
	"fmt"
	"strings"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/domain"
	mapCommon "github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
)

// MapResponder: A map responder, which is responsible for receiving client's request. Only read from db.
type MapResponder struct {
	conn            db.Conn
	getProofLimiter chan struct{}
	smt             *trie.Trie
}

// NewMapResponder: return a new responder
func NewMapResponder(ctx context.Context, root []byte, cacheHeight int) (*MapResponder, error) {
	// new db connection for SMT
	conn, err := db.Connect(nil)
	if err != nil {
		return nil, fmt.Errorf("NewMapResponder | Connect | %w", err)
	}

	smt, err := trie.NewTrie(root, common.SHA256Hash, conn)
	if err != nil {
		return nil, fmt.Errorf("NewMapResponder | NewTrie | %w", err)
	}
	smt.CacheHeightLimit = cacheHeight

	// load cache
	err = smt.LoadCache(ctx, root)
	if err != nil {
		return nil, fmt.Errorf("NewMapResponder | LoadCache | %w", err)
	}

	return newMapResponder(conn, smt), nil
}

func newMapResponder(conn db.Conn, smt *trie.Trie) *MapResponder {
	return &MapResponder{
		conn:            conn,
		getProofLimiter: make(chan struct{}, 64), // limit getProof to 64 concurrent routines
		smt:             smt,
	}
}

// GetProof: get proofs for one domain
func (r *MapResponder) GetProof(ctx context.Context, domainName string) ([]mapCommon.MapServerResponse, error) {
	r.getProofLimiter <- struct{}{}
	defer func() { <-r.getProofLimiter }()
	return r.getProof(ctx, domainName)
}

// GetRoot: get current root of the smt
func (mapResponder *MapResponder) GetRoot() []byte {
	return mapResponder.smt.Root
}

// Close: close db
func (mapResponder *MapResponder) Close() error {
	err := mapResponder.conn.Close()
	if err != nil {
		return err
	}
	return mapResponder.smt.Close()
}

func (r *MapResponder) getProof(ctx context.Context, domainName string) (
	[]mapCommon.MapServerResponse, error) {

	// check domain name first
	domainList, err := domain.ParseDomainName(domainName)
	if err != nil {
		if err == domain.ErrInvalidDomainName {
			return nil, err
		}
		return nil, fmt.Errorf("GetDomainProof | parseDomainName | %w", err)
	}
	proofsResult := make([]mapCommon.MapServerResponse, 0, len(domainList))

	for _, domain := range domainList {
		domainHash := common.SHA256Hash32Bytes([]byte(domain))

		proof, isPoP, proofKey, ProofValue, err := r.smt.MerkleProof(ctx, domainHash[:])
		if err != nil {
			return nil, fmt.Errorf("getDomainProof | MerkleProof | %w", err)
		}

		var proofType mapCommon.ProofType
		domainBytes := []byte{}
		// If it is PoP, query the domain entry. If it is PoA, directly return the PoA
		if isPoP {
			proofType = mapCommon.PoP
			domainBytes, err = r.conn.RetrieveDomainEntry(ctx, domainHash)
			if err != nil {
				return nil, fmt.Errorf("GetDomainProof | %w", err)
			}
		} else {
			proofType = mapCommon.PoA
		}

		proofsResult = append(proofsResult, mapCommon.MapServerResponse{
			Domain: domain,
			PoI: mapCommon.PoI{
				Proof:      proof,
				Root:       r.smt.Root,
				ProofType:  proofType,
				ProofKey:   proofKey,
				ProofValue: ProofValue},
			DomainEntryBytes: domainBytes,
		})
	}
	return proofsResult, nil
}

func (mapResponder *MapResponder) GetDomainProofs(ctx context.Context, domainNames []string) (map[string][]*mapCommon.MapServerResponse, error) {
	domainResultMap, domainProofMap, err := getMapping(domainNames)
	if err != nil {
		return nil, fmt.Errorf("GetDomainProofs | getMapping | %w", err)
	}

	domainToFetch, err := mapResponder.getProofFromSMT(ctx, domainProofMap)
	if err != nil {
		return nil, fmt.Errorf("GetDomainProofs | getProofFromSMT | %w", err)
	}

	result, err := mapResponder.conn.RetrieveDomainEntries(ctx, domainToFetch)
	if err != nil {
		return nil, fmt.Errorf("GetDomainProofs | RetrieveKeyValuePairMultiThread | %w", err)
	}
	for _, keyValuePair := range result {
		domainProofMap[keyValuePair.Key].DomainEntryBytes = keyValuePair.Value
	}

	return domainResultMap, nil
}

func getMapping(domainNames []string) (map[string][]*mapCommon.MapServerResponse, map[common.SHA256Output]*mapCommon.MapServerResponse, error) {
	domainResultMap := make(map[string][]*mapCommon.MapServerResponse)
	domainProofMap := make(map[common.SHA256Output]*mapCommon.MapServerResponse)

	for _, domainName := range domainNames {
		_, ok := domainResultMap[domainName]
		if !ok {
			// list of proofs for this domain
			resultsList := []*mapCommon.MapServerResponse{}
			subDomainNames, err := domain.ParseDomainName(domainName)

			if err != nil {
				return nil, nil, fmt.Errorf("getMapping | parseDomainName | %w", err)
			}
			for _, subDomainName := range subDomainNames {
				var domainHash32Bytes common.SHA256Output
				copy(domainHash32Bytes[:], common.SHA256Hash([]byte(subDomainName)))
				subDomainResult, ok := domainProofMap[domainHash32Bytes]
				if ok {
					resultsList = append(resultsList, subDomainResult)
				} else {
					domainProofMap[domainHash32Bytes] = &mapCommon.MapServerResponse{Domain: subDomainName}
					resultsList = append(resultsList, domainProofMap[domainHash32Bytes])
				}
			}
			domainResultMap[domainName] = resultsList
		}
	}
	return domainResultMap, domainProofMap, nil
}

func (mapResponder *MapResponder) getProofFromSMT(ctx context.Context, domainMap map[common.SHA256Output]*mapCommon.MapServerResponse) ([]common.SHA256Output, error) {
	domainNameToFetchFromDB := []common.SHA256Output{}
	for key, value := range domainMap {
		proof, isPoP, proofKey, ProofValue, err := mapResponder.smt.MerkleProof(ctx, key[:])
		if err != nil {
			return nil, fmt.Errorf("getProofFromSMT | MerkleProof | %w", err)
		}

		value.PoI = mapCommon.PoI{Proof: proof, ProofKey: proofKey, ProofValue: ProofValue, Root: mapResponder.smt.Root}

		switch {
		case isPoP:
			value.PoI.ProofType = mapCommon.PoP
			domainNameToFetchFromDB = append(domainNameToFetchFromDB, key)

		case !isPoP:
			value.PoI.ProofType = mapCommon.PoA
		}
	}
	return domainNameToFetchFromDB, nil
}

// repeatStmt returns  ( (?,..inner..,?), ...outer...  )
func repeatStmt(outer int, inner int) string {
	components := make([]string, inner)
	for i := 0; i < len(components); i++ {
		components[i] = "?"
	}
	toRepeat := "(" + strings.Join(components, ",") + ")"
	return strings.Repeat(toRepeat+",", outer-1) + toRepeat
}
