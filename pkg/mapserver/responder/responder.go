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
		switch {
		case isPoP:
			proofType = mapCommon.PoP
			result, err := r.conn.RetrieveOneKeyValuePairDomainEntries(ctx, domainHash)
			if err != nil {
				return nil, fmt.Errorf("GetDomainProof | RetrieveOneKeyValuePairDomainEntries | %w", err)
			}

			domainBytes = result.Value
		case !isPoP:
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
