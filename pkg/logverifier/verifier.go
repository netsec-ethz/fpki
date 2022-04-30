package logverifier

import (
	"errors"
	"fmt"

	"github.com/google/trillian"
	"github.com/google/trillian/types"
	"github.com/transparency-dev/merkle"
	"github.com/transparency-dev/merkle/rfc6962"
)

// LogVerifier: verifier is used to verify the proof from log
type LogVerifier struct {
	hasher merkle.LogHasher
	v      merkle.LogVerifier
}

//NewLogVerifier: retutn a new log verifier
func NewLogVerifier(hasher merkle.LogHasher) *LogVerifier {
	if hasher == nil {
		hasher = rfc6962.DefaultHasher
	}

	return &LogVerifier{
		hasher: hasher,
		v:      merkle.NewLogVerifier(hasher),
	}
}

// HashLeaf: hash the input
func (logVerifier *LogVerifier) HashLeaf(input []byte) []byte {
	return logVerifier.hasher.HashLeaf(input)
}

// VerifyInclusionWithPrevLogRoot: This function verify the leaf using an old log root(tree head)
// Logic: Verify the leaf using old log root -> verify the old root using the newest root
func (c *LogVerifier) VerifyInclusionWithPrevLogRoot(trusted *types.LogRootV1, newRoot *types.LogRootV1,
	consistency [][]byte, leafHash []byte, proof []*trillian.Proof) error {
	switch {
	case trusted == nil:
		return fmt.Errorf("VerifyInclusion_WithPrevLogRoot() error: trusted == nil")
	case newRoot == nil:
		return fmt.Errorf("VerifyInclusion_WithPrevLogRoot() error: newRoot == nil")
	}

	err := c.VerifyInclusionByHash(trusted, leafHash, proof)
	if err != nil {
		return fmt.Errorf("VerifyInclusionWithPrevLogRoot | VerifyInclusionByHash | %w", err)
	}

	// TODO(Yongzhe): compare two tree heads. If they are the same, directly return nil.
	_, err = c.VerifyRoot(trusted, newRoot, consistency)
	if err != nil {
		return fmt.Errorf("VerifyInclusionWithPrevLogRoot | VerifyRoot | %w", err)
	}
	return nil
}

// VerifyRoot: verifies that newRoot is a valid append-only operation from
// trusted root. If trusted.TreeSize is zero, a consistency proof is not needed.
func (c *LogVerifier) VerifyRoot(trusted *types.LogRootV1,
	newRoot *types.LogRootV1, consistency [][]byte) (*types.LogRootV1, error) {
	switch {
	case trusted == nil:
		return nil, fmt.Errorf("VerifyRoot() error: trusted == nil")
	case newRoot == nil:
		return nil, fmt.Errorf("VerifyRoot() error: newRoot == nil")
	case trusted.TreeSize != 0:
		// Verify consistency proof.
		if err := c.v.VerifyConsistency(trusted.TreeSize, newRoot.TreeSize, trusted.RootHash,
			newRoot.RootHash, consistency); err != nil {
			return nil, fmt.Errorf("failed to verify consistency proof from %d->%d %x->%x: %v",
				trusted.TreeSize, newRoot.TreeSize, trusted.RootHash, newRoot.RootHash, err)
		}
	}
	return newRoot, nil
}

// VerifyInclusionByHash verifies that the inclusion proof for the given Merkle leafHash
// matches the given trusted root.
func (c *LogVerifier) VerifyInclusionByHash(trusted *types.LogRootV1, leafHash []byte,
	proofs []*trillian.Proof) error {
	switch {
	case trusted == nil:
		return fmt.Errorf("VerifyInclusionByHash() error: trusted == nil")
	case proofs == nil:
		return fmt.Errorf("VerifyInclusionByHash() error: proof == nil")
	}

	isVerified := false
	// as long as one proof is verified, the verification is successful.
	// Proofs might contains multiple proof for different leaves, while the content of each leaf is identical.
	// Trillian will return all the proofs for one content. So one successful verification is enough.
	for _, proof := range proofs {
		err := c.v.VerifyInclusion(uint64(proof.LeafIndex), trusted.TreeSize, leafHash,
			proof.Hashes, trusted.RootHash)
		if err == nil {
			isVerified = true
			break
		}
	}
	if !isVerified {
		return errors.New("Verificate fails!")
	}
	return nil
}
