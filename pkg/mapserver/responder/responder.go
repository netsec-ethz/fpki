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

type MapResponder struct {
	conn           db.Conn
	smt            *trie.Trie
	signedTreeHead []byte
}

func NewMapResponder(ctx context.Context, configFile string, conn db.Conn) (*MapResponder, error) {
	// Load root.
	var root []byte
	if rootID, err := conn.LoadRoot(ctx); err != nil {
		return nil, err
	} else if rootID != nil {
		root = rootID[:]
	}

	// Build the Sparse Merkle Tree (SMT).
	smt, err := trie.NewTrie(root, common.SHA256Hash, conn)
	if err != nil {
		return nil, fmt.Errorf("error loading SMT: %w", err)
	}

	r := &MapResponder{
		conn: conn,
		smt:  smt,
	}
	r.signTreeHead(configFile)
	return r, nil
}

func (r *MapResponder) GetProof(ctx context.Context, domainName string,
) ([]*mapCommon.MapServerResponse, error) {

	// Parse the domain name.
	domainParts, err := domain.ParseDomainName(domainName)
	if err != nil {
		return nil, err
	}

	// Prepare proof with the help of the SMT.
	proofList := make([]*mapCommon.MapServerResponse, len(domainParts))
	for i, domainPart := range domainParts {
		domainPartID := common.SHA256Hash32Bytes([]byte(domainPart))
		proof, isPoP, proofKey, proofValue, err := r.smt.MerkleProof(ctx, domainPartID[:])
		if err != nil {
			return nil, fmt.Errorf("error obtaining Merkle proof for %s: %w",
				domainPart, err)
		}

		// If it is a proof of presence, obtain the payload.
		de := &mapCommon.DomainEntry{
			DomainName: domainPart,
			DomainID:   &domainPartID,
		}
		proofType := mapCommon.PoA
		if isPoP {
			proofType = mapCommon.PoP
			de.CertIDsID, de.CertIDs, err =
				r.conn.RetrieveDomainCertificatesPayload(ctx, domainPartID)
			if err != nil {
				return nil, fmt.Errorf("error obtaining x509 payload for %s: %w", domainPart, err)
			}
			de.PolicyIDsID, de.PolicyIDs, err =
				r.conn.RetrieveDomainPoliciesPayload(ctx, domainPartID)
			if err != nil {
				return nil, fmt.Errorf("error obtaining policies payload for %s: %w",
					domainPart, err)
			}
			// Concat certIDs with polIDs, in alphabetically sorted order.
			allIDs := append(common.BytesToIDs(de.CertIDs), common.BytesToIDs(de.PolicyIDs)...)
			v := common.SortIDsAndGlue(allIDs)
			vID := common.SHA256Hash32Bytes(v)
			de.DomainValue = &vID

			// TODO(juagargi) the sorting and concatenation should happen inside the DB.
		}

		proofList[i] = &mapCommon.MapServerResponse{
			DomainEntry: de,
			PoI: mapCommon.PoI{
				ProofType:  proofType,
				Proof:      proof,
				Root:       r.smt.Root,
				ProofKey:   proofKey,
				ProofValue: proofValue,
			},
			// TreeHeadSig: , TODO(juagargi)
		}
	}
	return proofList, nil
}

func (r *MapResponder) signTreeHead(configFile string) error {
	// Load configuration.
	config := &MapserverConfig{}
	err := ReadConfigFromFile(config, configFile)
	if err != nil {
		return fmt.Errorf("ReadConfigFromFile | %w", err)
	}

	// Load private key from configuration.
	keyPair, err := common.LoadRSAKeyPairFromFile(config.KeyPath)
	if err != nil {
		return fmt.Errorf("LoadRSAKeyPairFromFile | %w", err)
	}

	// Sign the tree head.
	signature, err := common.SignStructRSASHA256(r.smt.Root, keyPair)
	if err != nil {
		return fmt.Errorf("SignStructRSASHA256 | %w", err)
	}

	// Keep it for the proofs.
	r.signedTreeHead = signature

	return nil
}
