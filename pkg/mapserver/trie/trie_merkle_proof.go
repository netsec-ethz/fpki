/**
 *  @file
 *  @copyright defined in aergo/LICENSE.txt
 */

package trie

import (
	"bytes"
	"context"

	"github.com/netsec-ethz/fpki/pkg/common"
)

// MerkleProof generates a Merkle proof of inclusion or non-inclusion
// for the current trie root
// returns the audit path, bool (key included), key, value, error
// (key,value) can be 1- (nil, value), value of the included key, 2- the kv of a LeafNode
// on the path of the non-included key, 3- (nil, nil) for a non-included key
// with a DefaultLeaf on the path
func (s *Trie) MerkleProof(ctx context.Context, key []byte) ([][]byte, bool, []byte, []byte, error) {
	return s.MerkleProofR(ctx, key, s.Root)
}

// MerkleProofPast generates a Merkle proof of inclusion or non-inclusion
// for a given past trie root
// returns the audit path, bool (key included), key, value, error
// (key,value) can be 1- (nil, value), value of the included key, 2- the kv of a LeafNode
// on the path of the non-included key, 3- (nil, nil) for a non-included key
// with a DefaultLeaf on the path
func (s *Trie) MerkleProofR(ctx context.Context, key, root []byte) ([][]byte, bool, []byte, []byte, error) {
	auditPath := make([][]byte, 0, 32) // 32 levels should cover the whole tree: no new allocations
	s.lock.RLock()
	defer s.lock.RUnlock()
	s.atomicUpdate = false // so loadChildren doesn't return a copy
	included, newKey, value, err := s.merkleProof(ctx, &auditPath, root, key, nil, s.TrieHeight, 0)
	return auditPath, included, newKey, value, err
}

// MerkleProofCompressed returns a compressed merkle proof in the given trie
func (s *Trie) MerkleProofCompressedR(ctx context.Context, key, root []byte) ([]byte, [][]byte, int, bool, []byte, []byte, error) {
	return s.merkleProofCompressed(ctx, key, root)
}

// MerkleProofCompressed returns a compressed merkle proof
func (s *Trie) MerkleProofCompressed(ctx context.Context, key []byte) ([]byte, [][]byte, int, bool, []byte, []byte, error) {
	return s.merkleProofCompressed(ctx, key, s.Root)
}

func (s *Trie) merkleProofCompressed(ctx context.Context, key, root []byte) ([]byte, [][]byte, int, bool, []byte, []byte, error) {
	mpFull := make([][]byte, 0, 32) // 32 levels should cover the whole tree: no new allocations
	s.lock.RLock()
	defer s.lock.RUnlock()
	s.atomicUpdate = false // so loadChildren doesn't return a copy
	// create a regular merkle proof and then compress it
	included, proofKey, proofVal, err := s.merkleProof(ctx, &mpFull, root, key, nil, s.TrieHeight, 0)
	if err != nil {
		return nil, nil, 0, true, nil, nil, err
	}
	// the height of the shortcut in the tree will be needed for the proof verification
	height := len(mpFull)
	var mp [][]byte
	bitmap := make([]byte, len(mpFull)/8+1)
	for i, node := range mpFull {
		if !bytes.Equal(node, DefaultLeaf) {
			bitSet(bitmap, i)
			mp = append(mp, node)
		}
	}
	return bitmap, mp, height, included, proofKey, proofVal, nil
}

// merkleProof generates a Merkle proof of inclusion or non-inclusion
// for a given trie root.
// auditPath is the returned audit path (passed by reference).
// returns bool (key included), key, value, error
// (key,value) can be 1- (nil, value), value of the included key, 2- the kv of a LeafNode
// on the path of the non-included key, 3- (nil, nil) for a non-included key
// with a DefaultLeaf on the path
func (s *Trie) merkleProof(ctx context.Context, auditPath *[][]byte, root, key []byte,
	batch [][]byte, height, iBatch int) (bool, []byte, []byte, error) {

	// pathToReturn := make([][]byte, 0, 32) // we estimate 32 levels is enough to cover all tree
	if len(root) == 0 {
		// prove that an empty subtree is on the path of the key
		return false, nil, nil, nil
	}
	// Fetch the children of the node
	batch, iBatch, lnode, rnode, isShortcut, err := s.loadChildren(ctx, root, height, iBatch, batch)
	if err != nil {
		return false, nil, nil, err
	}
	if isShortcut || height == 0 {
		if bytes.Equal(lnode[:HashLength], key) {
			// return the value so a call to trie.Get() is not needed.
			return true, nil, rnode[:HashLength], nil
		}
		// Return the proof of the leaf key that is on the path of the non included key
		return false, lnode[:HashLength], rnode[:HashLength], nil
	}

	// append the left or right node to the proof
	if bitIsSet(key, s.TrieHeight-height) {
		included, proofKey, proofValue, err := s.merkleProof(ctx, auditPath, rnode, key, batch, height-1, 2*iBatch+2)
		if err != nil {
			return false, nil, nil, err
		}
		if len(lnode) != 0 {
			*auditPath = append(*auditPath, lnode[:HashLength])
			return included, proofKey, proofValue, nil
		} else {
			*auditPath = append(*auditPath, DefaultLeaf)
			return included, proofKey, proofValue, nil
		}

	}
	included, proofKey, proofValue, err := s.merkleProof(ctx, auditPath, lnode, key, batch, height-1, 2*iBatch+1)
	if err != nil {
		return false, nil, nil, err
	}
	if len(rnode) != 0 {
		*auditPath = append(*auditPath, rnode[:HashLength])
		return included, proofKey, proofValue, nil
	} else {
		*auditPath = append(*auditPath, DefaultLeaf)
		return included, proofKey, proofValue, nil
	}
}

// VerifyInclusion verifies that key/value is included in the trie with latest root
func VerifyInclusion(root []byte, ap [][]byte, key, value []byte) bool {
	leafHash := common.SHA256Hash(key, value, []byte{byte(256 - len(ap))})
	return bytes.Equal(root, verifyInclusion(ap, 0, key, leafHash))
}

// verifyInclusion returns the merkle root by hashing the merkle proof items
func verifyInclusion(ap [][]byte, keyIndex int, key, leafHash []byte) []byte {
	if keyIndex == len(ap) {
		return leafHash
	}
	if bitIsSet(key, keyIndex) {
		return common.SHA256Hash(ap[len(ap)-keyIndex-1], verifyInclusion(ap, keyIndex+1, key, leafHash))
	}
	return common.SHA256Hash(verifyInclusion(ap, keyIndex+1, key, leafHash), ap[len(ap)-keyIndex-1])
}

// VerifyNonInclusion verifies a proof of non inclusion,
// Returns true if the non-inclusion is verified
func VerifyNonInclusion(root []byte, ap [][]byte, key, value, proofKey []byte) bool {
	if root == nil {
		return true
	}
	// Check if an empty subtree is on the key path
	if len(proofKey) == 0 {
		// return true if a DefaultLeaf in the key path is included in the trie
		return bytes.Equal(root, verifyInclusion(ap, 0, key, DefaultLeaf))
	}
	// Check if another kv leaf is on the key path in 2 steps
	// 1- Check the proof leaf exists
	if !VerifyInclusion(root, ap, proofKey, value) {
		// the proof leaf is not included in the trie
		return false
	}
	// 2- Check the proof leaf is on the key path
	var b int
	for b = 0; b < len(ap); b++ {
		if bitIsSet(key, b) != bitIsSet(proofKey, b) {
			// the proofKey leaf node is not on the path of the key
			return false
		}
	}
	// return true because we verified another leaf is on the key path
	return true
}

// VerifyInclusionC verifies that key/value is included in the trie with latest root
func (s *Trie) VerifyInclusionC(bitmap, key, value []byte, ap [][]byte, length int) bool {
	leafHash := s.hash(key, value, []byte{byte(s.TrieHeight - length)})
	return bytes.Equal(s.Root, s.verifyInclusionC(bitmap, key, leafHash, ap, length, 0, 0))
}

// verifyInclusionC returns the merkle root by hashing the merkle proof items
func (s *Trie) verifyInclusionC(bitmap, key, leafHash []byte, ap [][]byte, length, keyIndex, apIndex int) []byte {
	if keyIndex == length {
		return leafHash
	}
	if bitIsSet(key, keyIndex) {
		if bitIsSet(bitmap, length-keyIndex-1) {
			return s.hash(ap[len(ap)-apIndex-1], s.verifyInclusionC(bitmap, key, leafHash, ap, length, keyIndex+1, apIndex+1))
		}
		return s.hash(DefaultLeaf, s.verifyInclusionC(bitmap, key, leafHash, ap, length, keyIndex+1, apIndex))

	}
	if bitIsSet(bitmap, length-keyIndex-1) {
		return s.hash(s.verifyInclusionC(bitmap, key, leafHash, ap, length, keyIndex+1, apIndex+1), ap[len(ap)-apIndex-1])
	}
	return s.hash(s.verifyInclusionC(bitmap, key, leafHash, ap, length, keyIndex+1, apIndex), DefaultLeaf)
}

// VerifyNonInclusionC verifies a proof of non inclusion,
// Returns true if the non-inclusion is verified
func (s *Trie) VerifyNonInclusionC(ap [][]byte, length int, bitmap, key, value, proofKey []byte) bool {
	// Check if an empty subtree is on the key path
	if len(proofKey) == 0 {
		// return true if a DefaultLeaf in the key path is included in the trie
		return bytes.Equal(s.Root, s.verifyInclusionC(bitmap, key, DefaultLeaf, ap, length, 0, 0))
	}
	// Check if another kv leaf is on the key path in 2 steps
	// 1- Check the proof leaf exists
	if !s.VerifyInclusionC(bitmap, proofKey, value, ap, length) {
		// the proof leaf is not included in the trie
		return false
	}
	// 2- Check the proof leaf is on the key path
	var b int
	for b = 0; b < length; b++ {
		if bitIsSet(key, b) != bitIsSet(proofKey, b) {
			// the proofKey leaf node is not on the path of the key
			return false
		}
	}
	// return true because we verified another leaf is on the key path
	return true
}
