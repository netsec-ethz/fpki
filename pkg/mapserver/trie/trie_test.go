/**
 *  @file
 *  @copyright defined in aergo/LICENSE.txt
 */

package trie

import (
	"bytes"
	"context"
	"math/rand"
	"sort"
	"testing"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/stretchr/testify/require"
)

// TestTrieEmpty: test empty SMT
func TestTrieEmpty(t *testing.T) {
	db := &MockDB{}
	smt, err := NewTrie(nil, common.SHA256Hash, db)
	require.NoError(t, err)

	if len(smt.Root) != 0 {
		t.Fatal("empty trie root hash not correct")
	}
}

// TestTrieUpdateAndGet: Update leaves and get leaves
func TestTrieUpdateAndGet(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	db := &MockDB{}
	smt, err := NewTrie(nil, common.SHA256Hash, db)
	require.NoError(t, err)

	smt.atomicUpdate = false

	// Add data to empty trie
	keys := getFreshData(10, 32)
	values := getFreshData(10, 32)
	ch := make(chan mResult, 1)
	smt.update(ctx, smt.Root, keys, values, nil, 0, smt.TrieHeight, ch)
	res := <-ch
	root := res.update

	// Check all keys have been stored
	for i, key := range keys {
		value, _ := smt.get(ctx, root, key, nil, 0, smt.TrieHeight)
		if !bytes.Equal(values[i], value) {
			t.Fatal("value not updated")
		}
	}

	// Add another new leaves
	newKeys := getFreshData(5, 32)
	newValues := getFreshData(5, 32)
	ch = make(chan mResult, 1)
	smt.update(ctx, root, newKeys, newValues, nil, 0, smt.TrieHeight, ch)
	res = <-ch
	newRoot := res.update
	if bytes.Equal(root, newRoot) {
		t.Fatal("trie not updated")
	}
	for i, newKey := range newKeys {
		newValue, _ := smt.get(ctx, newRoot, newKey, nil, 0, smt.TrieHeight)
		if !bytes.Equal(newValues[i], newValue) {
			t.Fatal("failed to get value")
		}
	}
}

// TestTrieAtomicUpdate: test AtomicUpdate()
func TestTrieAtomicUpdate(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	db := &MockDB{}
	smt, err := NewTrie(nil, common.SHA256Hash, db)
	require.NoError(t, err)

	smt.CacheHeightLimit = 0
	keys := getFreshData(1, 32)
	values := getFreshData(1, 32)
	root, _ := smt.AtomicUpdate(ctx, keys, values)
	updatedNb := len(smt.db.updatedNodes)
	cacheNb := len(smt.db.liveCache)
	newValues := getFreshData(1, 32)
	smt.AtomicUpdate(ctx, keys, newValues)
	if len(smt.db.updatedNodes) != 2*updatedNb {
		t.Fatal("Atomic update doesn't store all tries")
	}
	if len(smt.db.liveCache) != cacheNb {
		t.Fatal("Cache size should remain the same")
	}

	// check keys of previous atomic update are accessible in
	// updated nodes with root.
	smt.atomicUpdate = false
	for i, key := range keys {
		value, _ := smt.get(ctx, root, key, nil, 0, smt.TrieHeight)
		if !bytes.Equal(values[i], value) {
			t.Fatal("failed to get value")
		}
	}
}

// TestTriePublicUpdateAndGet: test Update() and verify the memory
func TestTriePublicUpdateAndGet(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	db := &MockDB{}
	smt, err := NewTrie(nil, common.SHA256Hash, db)
	require.NoError(t, err)

	smt.CacheHeightLimit = 0
	// Add data to empty trie
	keys := getFreshData(20, 32)
	values := getFreshData(20, 32)
	root, _ := smt.Update(ctx, keys, values)
	updatedNb := len(smt.db.updatedNodes)
	cacheNb := len(smt.db.liveCache)

	// Check all keys have been stored
	for i, key := range keys {
		value, _ := smt.Get(ctx, key)
		if !bytes.Equal(values[i], value) {
			t.Fatal("trie not updated")
		}
	}
	if !bytes.Equal(root, smt.Root) {
		t.Fatal("Root not stored")
	}

	newValues := getFreshData(20, 32)
	smt.Update(ctx, keys, newValues)

	if len(smt.db.updatedNodes) != updatedNb {
		t.Fatal("multiple updates don't actualize updated nodes")
	}
	if len(smt.db.liveCache) != cacheNb {
		t.Fatal("multiple updates don't actualize liveCache")
	}
	// Check all keys have been modified
	for i, key := range keys {
		value, _ := smt.Get(ctx, key)
		if !bytes.Equal(newValues[i], value) {
			t.Fatal("trie not updated")
		}
	}
}

// TestTrieUpdateAndDelete: test updating and deleting at the same time
func TestTrieUpdateAndDelete(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	db := &MockDB{}
	smt, err := NewTrie(nil, common.SHA256Hash, db)
	require.NoError(t, err)

	smt.CacheHeightLimit = 0
	key0 := make([]byte, 32, 32)
	values := getFreshData(1, 32)
	root, _ := smt.Update(ctx, [][]byte{key0}, values)
	cacheNb := len(smt.db.liveCache)
	updatedNb := len(smt.db.updatedNodes)
	smt.atomicUpdate = false
	_, _, k, v, isShortcut, _ := smt.loadChildren(ctx, root, smt.TrieHeight, 0, nil)
	if !isShortcut || !bytes.Equal(k[:HashLength], key0) || !bytes.Equal(v[:HashLength], values[0]) {
		t.Fatal("leaf shortcut didn't move up to root")
	}

	key1 := make([]byte, 32, 32)
	// set the last bit
	bitSet(key1, 255)
	keys := [][]byte{key0, key1}
	values = [][]byte{DefaultLeaf, getFreshData(1, 32)[0]}
	root, _ = smt.Update(ctx, keys, values)

	if len(smt.db.liveCache) != cacheNb {
		t.Fatal("number of cache nodes not correct after delete")
	}
	if len(smt.db.updatedNodes) != updatedNb {
		t.Fatal("number of cache nodes not correct after delete")
	}

	smt.atomicUpdate = false
	_, _, k, v, isShortcut, _ = smt.loadChildren(ctx, root, smt.TrieHeight, 0, nil)
	if !isShortcut || !bytes.Equal(k[:HashLength], key1) || !bytes.Equal(v[:HashLength], values[1]) {
		t.Fatal("leaf shortcut didn't move up to root")
	}
}

// TestTrieMerkleProof: test if merkle proof is correct
func TestTrieMerkleProof(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	db := &MockDB{}
	smt, err := NewTrie(nil, common.SHA256Hash, db)
	require.NoError(t, err)

	// Add data to empty trie
	keys := getFreshData(10, 32)
	values := getFreshData(10, 32)
	smt.Update(ctx, keys, values)

	for i, key := range keys {
		ap, _, k, v, _ := smt.MerkleProof(ctx, key)
		if !VerifyInclusion(smt.Root, ap, key, values[i]) {
			t.Fatalf("failed to verify inclusion proof")
		}
		if !bytes.Equal(key, k) && !bytes.Equal(values[i], v) {
			t.Fatalf("merkle proof didn't return the correct key-value pair")
		}
	}

	emptyKey := common.SHA256Hash([]byte("non-member"))
	ap, included, proofKey, proofValue, _ := smt.MerkleProof(ctx, emptyKey)
	if included {
		t.Fatalf("failed to verify non inclusion proof")
	}

	if !VerifyNonInclusion(smt.Root, ap, emptyKey, proofValue, proofKey) {
		t.Fatalf("failed to verify non inclusion proof")
	}
}

// TestTrieMerkleProofCompressed: compressed proofs test
func TestTrieMerkleProofCompressed(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	db := &MockDB{}
	smt, err := NewTrie(nil, common.SHA256Hash, db)
	require.NoError(t, err)

	// Add data to empty trie
	keys := getFreshData(10, 32)
	values := getFreshData(10, 32)
	smt.Update(ctx, keys, values)

	for i, key := range keys {
		bitmap, ap, length, _, k, v, _ := smt.MerkleProofCompressed(ctx, key)
		if !smt.VerifyInclusionC(bitmap, key, values[i], ap, length) {
			t.Fatalf("failed to verify inclusion proof")
		}
		if !bytes.Equal(key, k) && !bytes.Equal(values[i], v) {
			t.Fatalf("merkle proof didn't return the correct key-value pair")
		}
	}
	emptyKey := common.SHA256Hash([]byte("non-member"))
	bitmap, ap, length, included, proofKey, proofValue, _ := smt.MerkleProofCompressed(ctx, emptyKey)
	if included {
		t.Fatalf("failed to verify non inclusion proof")
	}
	if !smt.VerifyNonInclusionC(ap, length, bitmap, emptyKey, proofValue, proofKey) {
		t.Fatalf("failed to verify non inclusion proof")
	}
}

func TestHeight0LeafShortcut(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	keySize := 32
	db := &MockDB{}
	smt, err := NewTrie(nil, common.SHA256Hash, db)
	require.NoError(t, err)

	// Add 2 sibling keys that will be stored at height 0
	key0 := make([]byte, keySize, keySize)
	key1 := make([]byte, keySize, keySize)
	bitSet(key1, keySize*8-1)
	keys := [][]byte{key0, key1}
	values := getFreshData(2, 32)
	smt.Update(ctx, keys, values)
	updatedNb := len(smt.db.updatedNodes)

	// Check all keys have been stored
	for i, key := range keys {
		value, _ := smt.Get(ctx, key)
		if !bytes.Equal(values[i], value) {
			t.Fatal("trie not updated")
		}
	}
	bitmap, ap, length, _, k, v, err := smt.MerkleProofCompressed(ctx, key1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key1, k) && !bytes.Equal(values[1], v) {
		t.Fatalf("merkle proof didn't return the correct key-value pair")
	}
	if length != smt.TrieHeight {
		t.Fatal("proof should have length equal to trie height for a leaf shortcut")
	}
	if !smt.VerifyInclusionC(bitmap, key1, values[1], ap, length) {
		t.Fatal("failed to verify inclusion proof")
	}

	// Delete one key and check that the remaining one moved up to the root of the tree
	newRoot, _ := smt.AtomicUpdate(ctx, keys[0:1], [][]byte{DefaultLeaf})

	// Nb of updated nodes remains same because the new shortcut root was already stored at height 0.
	if len(smt.db.updatedNodes) != updatedNb {
		t.Fatal("number of cache nodes not correct after delete")
	}
	smt.atomicUpdate = false
	_, _, k, v, isShortcut, err := smt.loadChildren(ctx, newRoot, smt.TrieHeight, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !isShortcut || !bytes.Equal(k[:HashLength], key1) || !bytes.Equal(v[:HashLength], values[1]) {
		t.Fatal("leaf shortcut didn't move up to root")
	}

	_, _, length, _, k, v, _ = smt.MerkleProofCompressed(ctx, key1)
	if length != 0 {
		t.Fatal("proof should have length equal to trie height for a leaf shortcut")
	}
	if !bytes.Equal(key1, k) && !bytes.Equal(values[1], v) {
		t.Fatalf("merkle proof didn't return the correct key-value pair")
	}
}

func getFreshData(size, length int) [][]byte {
	var data [][]byte
	for i := 0; i < size; i++ {
		key := make([]byte, 32)
		_, err := rand.Read(key)
		if err != nil {
			panic(err)
		}
		data = append(data, common.SHA256Hash(key)[:length])
	}
	sort.Sort(DataArray(data))
	return data
}

type MockDB struct{}

// Close closes the connection.
func (d *MockDB) Close() error { return nil }

// RetrieveValue returns the value associated with the node.
func (d *MockDB) RetrieveValue(ctx context.Context, id db.FullID) ([]byte, error) { return nil, nil }

// RetrieveNode returns the value and the proof path (without the root) for a given node.
// Since each one of the steps of the proof path has a fixed size, returning the path
// as a slice is sufficient to know how many steps there were in the proof path.
func (d *MockDB) RetrieveNode(ctx context.Context, id db.FullID) ([]byte, []byte, error) {
	return nil, nil, nil
}

func (d *MockDB) RetrieveOneKeyValuePairTreeStruc(ctx context.Context, id common.SHA256Output) (*db.KeyValuePair, error) {
	return nil, nil
}

func (d *MockDB) RetrieveOneKeyValuePairDomainEntries(ctx context.Context, key common.SHA256Output) (*db.KeyValuePair, error) {
	return nil, nil
}

// RetrieveKeyValuePairFromTreeStruc: Retrieve a list of key-value pairs from Tree tables. Used by SMT lib.
func (d *MockDB) RetrieveKeyValuePairTreeStruc(ctx context.Context, id []common.SHA256Output, numOfRoutine int) ([]db.KeyValuePair, error) {
	return nil, nil
}

// RetrieveKeyValuePairFromDomainEntries: Retrieve a list of domain entries
func (d *MockDB) RetrieveKeyValuePairDomainEntries(ctx context.Context, id []common.SHA256Output, numOfRoutine int) ([]db.KeyValuePair, error) {
	return nil, nil
}
func (d *MockDB) RetrieveUpdatedDomainHashesUpdates(ctx context.Context, perQueryLimit int) ([]common.SHA256Output, error) {
	return nil, nil
}

func (d *MockDB) GetCountOfUpdatesDomainsUpdates(ctx context.Context) (int, error) { return 0, nil }

func (d *MockDB) UpdateKeyValuesDomainEntries(ctx context.Context, keyValuePairs []db.KeyValuePair) (int64, error) {
	return 0, nil
}

func (d *MockDB) UpdateKeyValuesTreeStruc(ctx context.Context, keyValuePairs []db.KeyValuePair) (int64, error) {
	return 0, nil
}

func (d *MockDB) DeleteKeyValuesTreeStruc(ctx context.Context, keys []common.SHA256Output) (int64, error) {
	return 0, nil
}

func (d *MockDB) AddUpdatedDomainHashesUpdates(ctx context.Context, keys []common.SHA256Output) (int64, error) {
	return 0, nil
}

func (d *MockDB) TruncateUpdatesTableUpdates(ctx context.Context) error { return nil }
