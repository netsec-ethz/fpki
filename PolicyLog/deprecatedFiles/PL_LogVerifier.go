package PL_LogClient

import (
	"errors"
	"fmt"

	"github.com/google/trillian"
	"github.com/google/trillian/types"
	"github.com/transparency-dev/merkle"
	"github.com/transparency-dev/merkle/rfc6962"
)

// LogVerifier allows verification of output from Trillian Logs, both regular
// and pre-ordered; it is safe for concurrent use (as its contents are fixed
// after construction).
type PL_LogVerifier struct {
	// hasher is the hash strategy used to compute nodes in the Merkle tree.
	hasher   merkle.LogHasher
	verifier merkle.LogVerifier
}

// NewLogVerifier returns an object that can verify output from Trillian Logs.
func NewLogVerifier(hasher merkle.LogHasher) *PL_LogVerifier {
	return &PL_LogVerifier{
		hasher:   hasher,
		verifier: merkle.NewLogVerifier(hasher),
	}
}

// NewLogVerifierFromTree creates a new LogVerifier using the algorithms
// specified by a Trillian Tree object.
func NewLogVerifierFromTree(config *trillian.Tree) (*PL_LogVerifier, error) {
	if config == nil {
		return nil, errors.New("client: NewLogVerifierFromTree(): nil config")
	}
	log, pLog := trillian.TreeType_LOG, trillian.TreeType_PREORDERED_LOG
	if got := config.TreeType; got != log && got != pLog {
		return nil, fmt.Errorf("client: NewLogVerifierFromTree(): TreeType: %v, want %v or %v", got, log, pLog)
	}

	return NewLogVerifier(rfc6962.DefaultHasher), nil
}

// VerifyRoot verifies that newRoot is a valid append-only operation from
// trusted. If trusted.TreeSize is zero, a consistency proof is not needed.
func (c *PL_LogVerifier) VerifyRoot(trusted *types.LogRootV1, newRoot *trillian.SignedLogRoot, consistency [][]byte) (*types.LogRootV1, error) {
	if trusted == nil {
		return nil, fmt.Errorf("VerifyRoot() error: trusted == nil")
	}
	if newRoot == nil {
		return nil, fmt.Errorf("VerifyRoot() error: newRoot == nil")
	}

	var r types.LogRootV1
	if err := r.UnmarshalBinary(newRoot.LogRoot); err != nil {
		return nil, err
	}

	// Implicitly trust the first root we get.
	if trusted.TreeSize != 0 {
		// Verify consistency proof.
		if err := c.v.VerifyConsistency(trusted.TreeSize, r.TreeSize, trusted.RootHash, r.RootHash, consistency); err != nil {
			return nil, fmt.Errorf("failed to verify consistency proof from %d->%d %x->%x: %v", trusted.TreeSize, r.TreeSize, trusted.RootHash, r.RootHash, err)
		}
	}
	return &r, nil
}

// VerifyInclusionByHash verifies that the inclusion proof for the given Merkle leafHash
// matches the given trusted root.
func (c *PL_LogVerifier) VerifyInclusionByHash(trusted *types.LogRootV1, leafHash []byte, proof *trillian.Proof) error {
	if trusted == nil {
		return fmt.Errorf("VerifyInclusionByHash() error: trusted == nil")
	}
	if proof == nil {
		return fmt.Errorf("VerifyInclusionByHash() error: proof == nil")
	}

	return c.v.VerifyInclusion(uint64(proof.LeafIndex), trusted.TreeSize, leafHash, proof.Hashes, trusted.RootHash)
}

// BuildLeaf runs the leaf hasher over data and builds a leaf.
// TODO: This can be misleading as it creates a partially
// filled LogLeaf. Consider returning a pair instead, or leafHash only.
func (c *PL_LogVerifier) BuildLeaf(data []byte) *trillian.LogLeaf {
	leafHash := c.hasher.HashLeaf(data)
	return &trillian.LogLeaf{
		LeafValue:      data,
		MerkleLeafHash: leafHash,
	}
}

func (c *PL_LogVerifier) BuildLeaves(data [][]byte) []*trillian.LogLeaf {
	leaves := []*trillian.LogLeaf{}
	for _, leaf := range data {
		leafOutput := c.BuildLeaf(leaf)
		leaves = append(leaves, leafOutput)
	}

	return leaves
}
