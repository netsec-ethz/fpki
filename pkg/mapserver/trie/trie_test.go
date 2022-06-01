/**
 *  @file
 *  @copyright defined in aergo/LICENSE.txt
 */

package trie

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"sort"
	"testing"

	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/stretchr/testify/require"
)

func TestTrieEmpty(t *testing.T) {
	db := &MockDB{}
	smt, err := NewTrie(nil, Hasher, db)
	require.NoError(t, err)

	if len(smt.Root) != 0 {
		t.Fatal("empty trie root hash not correct")
	}
}

func TestTrieUpdateAndGet(t *testing.T) {
	db := &MockDB{}
	smt, err := NewTrie(nil, Hasher, db)
	require.NoError(t, err)

	smt.atomicUpdate = false

	// Add data to empty trie
	keys := getFreshData(10, 32)
	values := getFreshData(10, 32)
	ch := make(chan mresult, 1)
	smt.update(smt.Root, keys, values, nil, 0, smt.TrieHeight, ch)
	res := <-ch
	root := res.update

	// Check all keys have been stored
	for i, key := range keys {
		value, _ := smt.get(root, key, nil, 0, smt.TrieHeight)
		if !bytes.Equal(values[i], value) {
			t.Fatal("value not updated")
		}
	}

	// Append to the trie
	newKeys := getFreshData(5, 32)
	newValues := getFreshData(5, 32)
	ch = make(chan mresult, 1)
	smt.update(root, newKeys, newValues, nil, 0, smt.TrieHeight, ch)
	res = <-ch
	newRoot := res.update
	if bytes.Equal(root, newRoot) {
		t.Fatal("trie not updated")
	}
	for i, newKey := range newKeys {
		newValue, _ := smt.get(newRoot, newKey, nil, 0, smt.TrieHeight)
		if !bytes.Equal(newValues[i], newValue) {
			t.Fatal("failed to get value")
		}
	}
}

func TestTrieAtomicUpdate(t *testing.T) {
	db := &MockDB{}
	smt, err := NewTrie(nil, Hasher, db)
	require.NoError(t, err)

	smt.CacheHeightLimit = 0
	keys := getFreshData(1, 32)
	values := getFreshData(1, 32)
	root, _ := smt.AtomicUpdate(keys, values)
	updatedNb := len(smt.db.updatedNodes)
	cacheNb := len(smt.db.liveCache)
	newvalues := getFreshData(1, 32)
	smt.AtomicUpdate(keys, newvalues)
	if len(smt.db.updatedNodes) != 2*updatedNb {
		t.Fatal("Atomic update doesnt store all tries")
	}
	if len(smt.db.liveCache) != cacheNb {
		t.Fatal("Cache size should remain the same")
	}

	// check keys of previous atomic update are accessible in
	// updated nodes with root.
	smt.atomicUpdate = false
	for i, key := range keys {
		value, _ := smt.get(root, key, nil, 0, smt.TrieHeight)
		if !bytes.Equal(values[i], value) {
			t.Fatal("failed to get value")
		}
	}
}

func TestTriePublicUpdateAndGet(t *testing.T) {
	db := &MockDB{}
	smt, err := NewTrie(nil, Hasher, db)
	require.NoError(t, err)

	smt.CacheHeightLimit = 0
	// Add data to empty trie
	keys := getFreshData(20, 32)
	values := getFreshData(20, 32)
	root, _ := smt.Update(keys, values)
	updatedNb := len(smt.db.updatedNodes)
	cacheNb := len(smt.db.liveCache)

	// Check all keys have been stored
	for i, key := range keys {
		value, _ := smt.Get(key)
		if !bytes.Equal(values[i], value) {
			t.Fatal("trie not updated")
		}
	}
	if !bytes.Equal(root, smt.Root) {
		t.Fatal("Root not stored")
	}

	newValues := getFreshData(20, 32)
	smt.Update(keys, newValues)

	if len(smt.db.updatedNodes) != updatedNb {
		t.Fatal("multiple updates don't actualise updated nodes")
	}
	if len(smt.db.liveCache) != cacheNb {
		t.Fatal("multiple updates don't actualise liveCache")
	}
	// Check all keys have been modified
	for i, key := range keys {
		value, _ := smt.Get(key)
		if !bytes.Equal(newValues[i], value) {
			t.Fatal("trie not updated")
		}
	}
}

// test updating and deleting at the same time
func TestTrieUpdateAndDelete(t *testing.T) {
	db := &MockDB{}
	smt, err := NewTrie(nil, Hasher, db)
	require.NoError(t, err)

	smt.CacheHeightLimit = 0
	key0 := make([]byte, 32, 32)
	values := getFreshData(1, 32)
	root, _ := smt.Update([][]byte{key0}, values)
	cacheNb := len(smt.db.liveCache)
	updatedNb := len(smt.db.updatedNodes)
	smt.atomicUpdate = false
	_, _, k, v, isShortcut, _ := smt.loadChildren(root, smt.TrieHeight, 0, nil)
	if !isShortcut || !bytes.Equal(k[:HashLength], key0) || !bytes.Equal(v[:HashLength], values[0]) {
		t.Fatal("leaf shortcut didn't move up to root")
	}

	key1 := make([]byte, 32, 32)
	// set the last bit
	bitSet(key1, 255)
	keys := [][]byte{key0, key1}
	values = [][]byte{DefaultLeaf, getFreshData(1, 32)[0]}
	root, _ = smt.Update(keys, values)

	if len(smt.db.liveCache) != cacheNb {
		t.Fatal("number of cache nodes not correct after delete")
	}
	if len(smt.db.updatedNodes) != updatedNb {
		t.Fatal("number of cache nodes not correct after delete")
	}

	smt.atomicUpdate = false
	_, _, k, v, isShortcut, _ = smt.loadChildren(root, smt.TrieHeight, 0, nil)
	if !isShortcut || !bytes.Equal(k[:HashLength], key1) || !bytes.Equal(v[:HashLength], values[1]) {
		t.Fatal("leaf shortcut didn't move up to root")
	}
}

func TestTrieMerkleProof(t *testing.T) {
	db := &MockDB{}
	smt, err := NewTrie(nil, Hasher, db)
	require.NoError(t, err)

	// Add data to empty trie
	keys := getFreshData(10, 32)
	values := getFreshData(10, 32)
	smt.Update(keys, values)

	for i, key := range keys {
		ap, _, k, v, _ := smt.MerkleProof(key)
		if !VerifyInclusion(smt.Root, ap, key, values[i]) {
			t.Fatalf("failed to verify inclusion proof")
		}
		if !bytes.Equal(key, k) && !bytes.Equal(values[i], v) {
			t.Fatalf("merkle proof didnt return the correct key-value pair")
		}
	}
	emptyKey := Hasher([]byte("non-member"))
	ap, included, proofKey, proofValue, _ := smt.MerkleProof(emptyKey)
	if included {
		t.Fatalf("failed to verify non inclusion proof")
	}
	if !VerifyNonInclusion(smt.Root, ap, emptyKey, proofValue, proofKey) {
		t.Fatalf("failed to verify non inclusion proof")
	}
}

func TestTrieMerkleProofCompressed(t *testing.T) {
	db := &MockDB{}
	smt, err := NewTrie(nil, Hasher, db)
	require.NoError(t, err)

	// Add data to empty trie
	keys := getFreshData(10, 32)
	values := getFreshData(10, 32)
	smt.Update(keys, values)

	for i, key := range keys {
		bitmap, ap, length, _, k, v, _ := smt.MerkleProofCompressed(key)
		if !smt.VerifyInclusionC(bitmap, key, values[i], ap, length) {
			t.Fatalf("failed to verify inclusion proof")
		}
		if !bytes.Equal(key, k) && !bytes.Equal(values[i], v) {
			t.Fatalf("merkle proof didnt return the correct key-value pair")
		}
	}
	emptyKey := Hasher([]byte("non-member"))
	bitmap, ap, length, included, proofKey, proofValue, _ := smt.MerkleProofCompressed(emptyKey)
	if included {
		t.Fatalf("failed to verify non inclusion proof")
	}
	if !smt.VerifyNonInclusionC(ap, length, bitmap, emptyKey, proofValue, proofKey) {
		t.Fatalf("failed to verify non inclusion proof")
	}
}

func TestHeight0LeafShortcut(t *testing.T) {
	keySize := 32
	db := &MockDB{}
	smt, err := NewTrie(nil, Hasher, db)
	require.NoError(t, err)

	// Add 2 sibling keys that will be stored at height 0
	key0 := make([]byte, keySize, keySize)
	key1 := make([]byte, keySize, keySize)
	bitSet(key1, keySize*8-1)
	keys := [][]byte{key0, key1}
	values := getFreshData(2, 32)
	smt.Update(keys, values)
	updatedNb := len(smt.db.updatedNodes)

	// Check all keys have been stored
	for i, key := range keys {
		value, _ := smt.Get(key)
		if !bytes.Equal(values[i], value) {
			t.Fatal("trie not updated")
		}
	}
	bitmap, ap, length, _, k, v, err := smt.MerkleProofCompressed(key1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key1, k) && !bytes.Equal(values[1], v) {
		t.Fatalf("merkle proof didnt return the correct key-value pair")
	}
	if length != smt.TrieHeight {
		t.Fatal("proof should have length equal to trie height for a leaf shortcut")
	}
	if !smt.VerifyInclusionC(bitmap, key1, values[1], ap, length) {
		t.Fatal("failed to verify inclusion proof")
	}

	// Delete one key and check that the remaining one moved up to the root of the tree
	newRoot, _ := smt.AtomicUpdate(keys[0:1], [][]byte{DefaultLeaf})

	// Nb of updated nodes remains same because the new shortcut root was already stored at height 0.
	if len(smt.db.updatedNodes) != updatedNb {
		fmt.Println(len(smt.db.updatedNodes), updatedNb)
		t.Fatal("number of cache nodes not correct after delete")
	}
	smt.atomicUpdate = false
	_, _, k, v, isShortcut, err := smt.loadChildren(newRoot, smt.TrieHeight, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !isShortcut || !bytes.Equal(k[:HashLength], key1) || !bytes.Equal(v[:HashLength], values[1]) {
		t.Fatal("leaf shortcut didn't move up to root")
	}

	_, _, length, _, k, v, _ = smt.MerkleProofCompressed(key1)
	if length != 0 {
		t.Fatal("proof should have length equal to trie height for a leaf shortcut")
	}
	if !bytes.Equal(key1, k) && !bytes.Equal(values[1], v) {
		t.Fatalf("merkle proof didnt return the correct key-value pair")
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
		data = append(data, Hasher(key)[:length])
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

func (d *MockDB) RetrieveOneKeyValuePair(ctx context.Context, id string, tableName db.TableName) (*db.KeyValuePair, error) {
	return nil, nil
}

func (d *MockDB) RetrieveKeyValuePairMultiThread(ctx context.Context, id []string, numOfRoutine int, tableName db.TableName) ([]db.KeyValuePair, error) {
	return nil, nil
}

func (d *MockDB) RetrieveUpdatedDomainMultiThread(ctx context.Context, perQueryLimit int) ([]string, error) {
	return nil, nil
}

func (d *MockDB) CountUpdates(ctx context.Context) (int, error) { return 0, nil }

func (d *MockDB) UpdateKeyValues(ctx context.Context, keyValuePairs []db.KeyValuePair, tableName db.TableName) (error, int) {
	return nil, 0
}

func (d *MockDB) DeleteKeyValues(ctx context.Context, keys []string, tableName db.TableName) error {
	return nil
}

func (d *MockDB) ReplaceKeys(ctx context.Context, keys []string) (int, error) {
	return 0, nil
}

func (d *MockDB) TruncateUpdatesTable(ctx context.Context) error { return nil }

func (d *MockDB) DisableKeys() error { return nil }

func (d *MockDB) EnableKeys() error { return nil }
