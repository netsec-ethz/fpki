/**
 *  @file
 *  @copyright defined in aergo/LICENSE.txt
 */

package trie

import (
	"context"
	"math/rand"
	"sort"
	"testing"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/tests/testdb"
	"github.com/stretchr/testify/require"
)

// TestTrieEmpty: test empty SMT
func TestTrieEmpty(t *testing.T) {
	db := testdb.NewMockDB()
	smt, err := NewTrie(nil, common.SHA256Hash, db)
	require.NoError(t, err)

	require.Empty(t, smt.Root)
}

// TestTrieUpdateAndGet: Update leaves and get leaves
func TestTrieUpdateAndGet(t *testing.T) {
	rand.Seed(1)
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	db := testdb.NewMockDB()
	smt, err := NewTrie(nil, common.SHA256Hash, db)
	require.NoError(t, err)

	smt.atomicUpdate = false

	// Add data to empty trie
	keys := getRandomData(t, 10)
	values := getRandomData(t, 10)
	ch := make(chan mResult, 1)
	smt.update(ctx, smt.Root, keys, values, nil, 0, smt.TrieHeight, ch)
	res := <-ch
	root := res.update

	// Check all keys have been stored
	for i, key := range keys {
		value, _ := smt.get(ctx, root, key, nil, 0, smt.TrieHeight)
		require.Equal(t, values[i], value)
	}

	// Add another new leaves
	newKeys := getRandomData(t, 5)
	newValues := getRandomData(t, 5)
	ch = make(chan mResult, 1)
	smt.update(ctx, root, newKeys, newValues, nil, 0, smt.TrieHeight, ch)
	res = <-ch
	newRoot := res.update
	require.NotEqual(t, root, newRoot)
	for i, newKey := range newKeys {
		newValue, _ := smt.get(ctx, newRoot, newKey, nil, 0, smt.TrieHeight)
		require.Equal(t, newValues[i], newValue)
	}
}

// TestTrieAtomicUpdate: test AtomicUpdate()
func TestTrieAtomicUpdate(t *testing.T) {
	rand.Seed(1)
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	db := testdb.NewMockDB()
	smt, err := NewTrie(nil, common.SHA256Hash, db)
	require.NoError(t, err)

	smt.CacheHeightLimit = 0
	keys := getRandomData(t, 1)
	values := getRandomData(t, 1)
	root, _ := smt.AtomicUpdate(ctx, keys, values)
	updatedNb := len(smt.db.updatedNodes)
	cacheNb := len(smt.db.liveCache)
	newValues := getRandomData(t, 1)
	smt.AtomicUpdate(ctx, keys, newValues)
	require.Len(t, smt.db.updatedNodes, 2*updatedNb)
	require.Len(t, smt.db.liveCache, cacheNb)

	// check keys of previous atomic update are accessible in
	// updated nodes with root.
	smt.atomicUpdate = false
	for i, key := range keys {
		value, _ := smt.get(ctx, root, key, nil, 0, smt.TrieHeight)
		require.Equal(t, values[i], value)
	}
}

// TestTriePublicUpdateAndGet: test Update() and verify the memory
func TestTriePublicUpdateAndGet(t *testing.T) {
	rand.Seed(1)
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	db := testdb.NewMockDB()
	smt, err := NewTrie(nil, common.SHA256Hash, db)
	require.NoError(t, err)

	smt.CacheHeightLimit = 0
	// Add data to empty trie
	keys := getRandomData(t, 20)
	values := getRandomData(t, 20)
	root, _ := smt.Update(ctx, keys, values)
	updatedNb := len(smt.db.updatedNodes)
	cacheNb := len(smt.db.liveCache)

	// Check all keys have been stored
	for i, key := range keys {
		value, _ := smt.Get(ctx, key)
		require.Equal(t, values[i], value)
	}
	require.Equal(t, root, smt.Root)

	newValues := getRandomData(t, 20)
	smt.Update(ctx, keys, newValues)

	require.Len(t, smt.db.updatedNodes, updatedNb)
	require.Len(t, smt.db.liveCache, cacheNb)
	// Check all keys have been modified
	for i, key := range keys {
		value, _ := smt.Get(ctx, key)
		require.Equal(t, newValues[i], value)
	}
}

// TestTrieUpdateAndDelete: test updating and deleting at the same time
func TestTrieUpdateAndDelete(t *testing.T) {
	rand.Seed(1)
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	db := testdb.NewMockDB()
	smt, err := NewTrie(nil, common.SHA256Hash, db)
	require.NoError(t, err)

	smt.CacheHeightLimit = 0
	key0 := make([]byte, 32)
	values := getRandomData(t, 1)
	root, _ := smt.Update(ctx, [][]byte{key0}, values)
	cacheNb := len(smt.db.liveCache)
	updatedNb := len(smt.db.updatedNodes)
	smt.atomicUpdate = false
	_, _, k, v, isShortcut, _ := smt.loadChildren(ctx, root, smt.TrieHeight, 0, nil)
	require.True(t, isShortcut)
	require.Equal(t, key0, k[:HashLength])
	require.Equal(t, values[0], v[:HashLength])

	key1 := make([]byte, 32)
	// set the last bit
	bitSet(key1, 255)
	keys := [][]byte{key0, key1}
	values = [][]byte{DefaultLeaf, getRandomData(t, 1)[0]}
	root, _ = smt.Update(ctx, keys, values)
	require.Len(t, smt.db.liveCache, cacheNb)
	require.Len(t, smt.db.updatedNodes, updatedNb)

	smt.atomicUpdate = false
	_, _, k, v, isShortcut, _ = smt.loadChildren(ctx, root, smt.TrieHeight, 0, nil)
	require.True(t, isShortcut)
	require.Equal(t, key1, k[:HashLength])
	require.Equal(t, values[1], v[:HashLength])
}

// TestTrieMerkleProof: test if merkle proof is correct
func TestTrieMerkleProof(t *testing.T) {
	rand.Seed(1)
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	db := testdb.NewMockDB()
	smt, err := NewTrie(nil, common.SHA256Hash, db)
	require.NoError(t, err)

	// Add data to empty trie
	keys := getRandomData(t, 10)
	values := getRandomData(t, 10)
	smt.Update(ctx, keys, values)

	for i, key := range keys {
		ap, _, k, v, _ := smt.MerkleProof(ctx, key)
		require.True(t, VerifyInclusion(smt.Root, ap, key, values[i]))
		// (key,value) can be 1- (nil, value), value of the included key, 2- the kv of a LeafNode
		// on the path of the non-included key, 3- (nil, nil) for a non-included key
		// with a DefaultLeaf on the path
		require.Nil(t, k)
		require.Equal(t, v, values[i])
	}

	emptyKey := common.SHA256Hash([]byte("non-member"))
	ap, included, proofKey, proofValue, _ := smt.MerkleProof(ctx, emptyKey)
	require.False(t, included)

	require.True(t, VerifyNonInclusion(smt.Root, ap, emptyKey, proofValue, proofKey))
}

// TestTrieMerkleProofCompressed: compressed proofs test
func TestTrieMerkleProofCompressed(t *testing.T) {
	rand.Seed(1)
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	db := testdb.NewMockDB()
	smt, err := NewTrie(nil, common.SHA256Hash, db)
	require.NoError(t, err)

	// Add data to empty trie
	keys := getRandomData(t, 10)
	values := getRandomData(t, 10)
	smt.Update(ctx, keys, values)

	for i, key := range keys {
		bitmap, ap, length, _, k, v, _ := smt.MerkleProofCompressed(ctx, key)
		require.True(t, smt.VerifyInclusionC(bitmap, key, values[i], ap, length))
		// (key,value) can be 1- (nil, value), value of the included key, 2- the kv of a LeafNode
		// on the path of the non-included key, 3- (nil, nil) for a non-included key
		// with a DefaultLeaf on the path
		require.Nil(t, k)
		require.Equal(t, values[i], v)
	}
	emptyKey := common.SHA256Hash([]byte("non-member"))
	bitmap, ap, length, included, proofKey, proofValue, _ := smt.MerkleProofCompressed(ctx, emptyKey)
	require.False(t, included)
	require.True(t, smt.VerifyNonInclusionC(ap, length, bitmap, emptyKey, proofValue, proofKey))
}

func TestHeight0LeafShortcut(t *testing.T) {
	rand.Seed(1)
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	keySize := 32
	db := testdb.NewMockDB()
	smt, err := NewTrie(nil, common.SHA256Hash, db)
	require.NoError(t, err)

	// Add 2 sibling keys that will be stored at height 0
	key0 := make([]byte, keySize, keySize)
	key1 := make([]byte, keySize, keySize)
	bitSet(key1, keySize*8-1)
	keys := [][]byte{key0, key1}
	values := getRandomData(t, 2)
	smt.Update(ctx, keys, values)
	updatedNb := len(smt.db.updatedNodes)

	// Check all keys have been stored
	for i, key := range keys {
		value, _ := smt.Get(ctx, key)
		require.Equal(t, values[i], value)
	}
	bitmap, ap, length, _, k, v, err := smt.MerkleProofCompressed(ctx, key1)
	require.NoError(t, err)
	// (key,value) can be 1- (nil, value), value of the included key, 2- the kv of a LeafNode
	// on the path of the non-included key, 3- (nil, nil) for a non-included key
	// with a DefaultLeaf on the path
	require.Nil(t, k)
	require.Equal(t, values[1], v)
	require.Equal(t, smt.TrieHeight, length)
	require.True(t, smt.VerifyInclusionC(bitmap, key1, values[1], ap, length))

	// Delete one key and check that the remaining one moved up to the root of the tree
	newRoot, _ := smt.AtomicUpdate(ctx, keys[0:1], [][]byte{DefaultLeaf})

	// Nb of updated nodes remains same because the new shortcut root was already stored at height 0.
	require.Len(t, smt.db.updatedNodes, updatedNb)
	smt.atomicUpdate = false
	_, _, k, v, isShortcut, err := smt.loadChildren(ctx, newRoot, smt.TrieHeight, 0, nil)
	require.NoError(t, err)
	require.True(t, isShortcut)
	require.Equal(t, key1, k[:HashLength])
	require.Equal(t, values[1], v[:HashLength])

	_, _, length, _, k, v, _ = smt.MerkleProofCompressed(ctx, key1)
	require.Equal(t, 0, length)
	// (key,value) can be 1- (nil, value), value of the included key, 2- the kv of a LeafNode
	// on the path of the non-included key, 3- (nil, nil) for a non-included key
	// with a DefaultLeaf on the path
	require.Nil(t, k)
	require.Equal(t, values[1], v)
}

func getRandomData(t require.TestingT, count int) [][]byte {
	data := make([][]byte, count)
	for i := 0; i < count; i++ {
		key := make([]byte, common.SHA256Size)
		_, err := rand.Read(key)
		require.NoError(t, err)
		data[i] = key
	}
	sort.Sort(DataArray(data))
	return data
}
