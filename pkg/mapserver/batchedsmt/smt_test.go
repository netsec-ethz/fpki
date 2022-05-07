package batchedsmt

import (
	"bytes"
	"database/sql"
	"math/rand"
	"runtime"
	"sort"
	"testing"
	"time"

	"fmt"

	_ "github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/require"
)

func TestSmtUpdateAndGet(t *testing.T) {
	db, err := sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/map?multiStatements=true")
	require.NoError(t, err, "db conn error")

	defer db.Close()
	smt, err := NewSMT(nil, Hasher, db)
	require.NoError(t, err, "smt creation error")

	// Add data to empty trie
	keys := getFreshData(10, 32)
	values := getFreshData(10, 32)
	ch := make(chan updateResult, 1)
	smt.update(smt.Root, keys, values, nil, 0, TreeHeight, false, true, ch)
	res := <-ch
	root := res.update

	// Check all keys have been stored
	for i, key := range keys {
		value, _ := smt.get(root, key, nil, 0, TreeHeight)
		if !bytes.Equal(values[i], value) {
			t.Fatal("value not updated")
		}
	}

	// Append to the trie
	newKeys := getFreshData(5, 32)
	newValues := getFreshData(5, 32)
	ch = make(chan updateResult, 1)
	smt.update(root, newKeys, newValues, nil, 0, TreeHeight, false, true, ch)
	res = <-ch
	newRoot := res.update
	if bytes.Equal(root, newRoot) {
		t.Fatal("trie not updated")
	}
	for i, newKey := range newKeys {
		newValue, _ := smt.get(newRoot, newKey, nil, 0, TreeHeight)
		if !bytes.Equal(newValues[i], newValue) {
			t.Fatal("failed to get value")
		}
	}
	// Check old keys are still stored
	for i, key := range keys {
		value, _ := smt.get(newRoot, key, nil, 0, TreeHeight)
		if !bytes.Equal(values[i], value) {
			t.Fatal("failed to get value")
		}
	}
}

func TestSmtPublicUpdateAndGet(t *testing.T) {
	db, err := sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/map?multiStatements=true")
	require.NoError(t, err, "db conn error")

	defer db.Close()

	smt, err := NewSMT(nil, Hasher, db)
	require.NoError(t, err, "smt creation error")

	smt.CacheHeightLimit = 0
	// Add data to empty trie
	keys := getFreshData(5, 32)
	values := getFreshData(5, 32)
	root, _ := smt.Update(keys, values)
	updatedNb := len(smt.db.updatedNodes)
	cacheNb := len(smt.db.cachedNodes)

	// Check all keys have been stored
	for i, key := range keys {
		value, _ := smt.GetLeafValue(key)
		if !bytes.Equal(values[i], value) {
			t.Fatal("trie not updated")
		}
	}
	if !bytes.Equal(root, smt.Root) {
		t.Fatal("Root not stored")
	}

	newValues := getFreshData(5, 32)
	smt.Update(keys, newValues)

	if len(smt.db.updatedNodes) != updatedNb {
		t.Fatal("multiple updates don't actualise updated nodes")
	}
	if len(smt.db.cachedNodes) != cacheNb {
		t.Fatal("multiple updates don't actualise liveCache")
	}

	// Check all keys have been modified
	for i, key := range keys {
		value, _ := smt.GetLeafValue(key)
		if !bytes.Equal(newValues[i], value) {
			t.Fatal("trie not updated")
		}
	}

	newKeys := getFreshData(5, 32)
	newValues = getFreshData(5, 32)
	smt.Update(newKeys, newValues)
	for i, key := range newKeys {
		value, _ := smt.GetLeafValue(key)
		if !bytes.Equal(newValues[i], value) {
			t.Fatal("trie not updated")
		}
	}
}

func TestSmtCommit(t *testing.T) {
	db, err := sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/map?multiStatements=true")
	require.NoError(t, err, "db conn error")

	defer db.Close()

	smt, err := NewSMT(nil, Hasher, db)
	require.NoError(t, err, "smt creation error")

	keys := getFreshData(32, 32)
	values := getFreshData(32, 32)
	smt.Update(keys, values)
	smt.StoreUpdatedNode()
	// liveCache is deleted so the key is fetched in the db
	smt.db.cachedNodes = make(map[Hash][][]byte)
	for i := range keys {
		value, _ := smt.GetLeafValue(keys[i])
		if !bytes.Equal(values[i], value) {
			t.Fatal("failed to get value in committed db")
		}
	}

	// test loading a shortcut batch
	smt, err = NewSMT(nil, Hasher, db)
	require.NoError(t, err, "smt creation error")

	keys = getFreshData(1, 32)
	values = getFreshData(1, 32)
	smt.Update(keys, values)
	smt.StoreUpdatedNode()
	// liveCache is deleted so the key is fetched in badger db
	smt.db.cachedNodes = make(map[Hash][][]byte)
	value, _ := smt.GetLeafValue(keys[0])
	if !bytes.Equal(values[0], value) {
		t.Fatal("failed to get value in new committed db")
	}
	db.Close()
}

func TestSmtMerkleProof(t *testing.T) {
	db, err := sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/map?multiStatements=true")
	require.NoError(t, err, "db conn error")

	defer db.Close()
	smt, err := NewSMT(nil, Hasher, db)
	require.NoError(t, err, "smt creation error")

	// Add data to empty trie
	keys := getFreshData(10, 32)
	values := getFreshData(10, 32)
	smt.Update(keys, values)

	domain := "example.com"
	domainHash := Hasher([]byte(domain))

	smt.Update([][]byte{domainHash}, [][]byte{Hasher([]byte("this is a test"))})

	proof, _ := smt.MerkleProof(domainHash)
	if !VerifyMerkleProof(smt.Root, proof, domainHash, Hasher([]byte("this is a test"))) {
		t.Fatalf("failed to verify inclusion proof for example.com")
	}

	smt.Update([][]byte{domainHash}, [][]byte{Hasher([]byte("this is not a test"))})

	proof, _ = smt.MerkleProof(domainHash)
	if VerifyMerkleProof(smt.Root, proof, domainHash, Hasher([]byte("this is a test"))) {
		t.Fatalf("failed to verify non inclusion proof for example.com after update")
	}

	if !VerifyMerkleProof(smt.Root, proof, domainHash, Hasher([]byte("this is not a test"))) {
		t.Fatalf("failed to verify inclusion proof for example.com after update")
	}

	for i, key := range keys {
		ap, _ := smt.MerkleProof(key)
		if !VerifyMerkleProof(smt.Root, ap, key, values[i]) {
			t.Fatalf("failed to verify inclusion proof")
		}
	}
	emptyKey := Hasher([]byte("non-member"))
	ap, _ := smt.MerkleProof(emptyKey)
	if !VerifyMerkleProof(smt.Root, ap, emptyKey, DefaultLeaf) {
		t.Fatalf("failed to verify non inclusion proof")
	}
}

func TestSmtMerkleProofCompressed(t *testing.T) {
	db, err := sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/map?multiStatements=true")
	require.NoError(t, err, "db conn error")

	defer db.Close()
	smt, err := NewSMT(nil, Hasher, db)
	require.NoError(t, err, "smt creation error")

	// Add data to empty trie
	keys := getFreshData(10, 32)
	values := getFreshData(10, 32)
	smt.Update(keys, values)

	for i, key := range keys {
		bitmap, ap, _ := smt.MerkleProofCompressed(key)
		bitmap2, ap2, _ := smt.MerkleProofCompressed2(key)
		if !smt.VerifyMerkleProofCompressed(bitmap, ap, key, values[i]) {
			t.Fatalf("failed to verify inclusion proof")
		}
		if !smt.VerifyMerkleProofCompressed(bitmap2, ap2, key, values[i]) {
			t.Fatalf("failed to verify inclusion proof")
		}
		if !bytes.Equal(bitmap, bitmap2) {
			t.Fatal("the 2 versions of compressed merkle proofs don't match")
		}
		for i, a := range ap {
			if !bytes.Equal(a, ap2[i]) {
				t.Fatal("the 2 versions of compressed merkle proofs don't match")
			}
		}
	}
	emptyKey := Hasher([]byte("non-member"))
	bitmap, ap, _ := smt.MerkleProofCompressed(emptyKey)
	if !smt.VerifyMerkleProofCompressed(bitmap, ap, emptyKey, DefaultLeaf) {
		t.Fatalf("failed to verify non inclusion proof")
	}
}

func TestSmtMerkleProofCompressed2(t *testing.T) {
	db, err := sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/map?multiStatements=true")
	require.NoError(t, err, "db conn error")

	defer db.Close()
	smt, err := NewSMT(nil, Hasher, db)
	require.NoError(t, err, "smt creation error")

	// Add data to empty trie
	keys := getFreshData(10, 32)
	values := getFreshData(10, 32)
	smt.Update(keys, values)

	for i, key := range keys {
		bitmap2, ap2, _ := smt.MerkleProofCompressed2(key)
		if !smt.VerifyMerkleProofCompressed(bitmap2, ap2, key, values[i]) {
			t.Fatalf("failed to verify inclusion proof")
		}
	}
}

func benchmark1MAccounts(smt *SMT, b *testing.B) ([][]byte, [][]byte) {
	fmt.Println("\nLoading b.N x 1000 accounts")
	allKeys := [][]byte{}
	allValues := [][]byte{}
	for i := 0; i < 10; i++ {
		fmt.Println("iteration ", i)
		newkeys := getFreshData(10000, 32)
		newvalues := getFreshData(10000, 32)
		allKeys = append(allKeys, newkeys...)
		allValues = append(allValues, newvalues...)

		start := time.Now()
		smt.Update(newkeys, newvalues)
		fmt.Println("update finished")
		end := time.Now()
		smt.StoreUpdatedNode()
		end2 := time.Now()
		for i, key := range newkeys {
			val, _ := smt.GetLeafValue(key)
			if !bytes.Equal(val, newvalues[i]) {
				b.Fatal("new key not included")
			}
		}
		end3 := time.Now()
		elapsed := end.Sub(start)
		elapsed2 := end2.Sub(end)
		elapsed3 := end3.Sub(end2)
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		fmt.Println(" : update time : ", elapsed, "commit time : ", elapsed2,
			"\n1000 Get time : ", elapsed3,
			"\ncache size : ", len(smt.db.cachedNodes),
			"\nRAM : ", m.Sys/1024/1024, " MiB")
	}

	return allKeys, allValues
}

func benchmarkGet1MProof(smt *SMT, keys [][]byte, values [][]byte) error {
	start := time.Now()
	fmt.Println(len(keys))
	for _, key := range keys {
		_, err := smt.MerkleProof(key)
		if err != nil {
			return err
		}
	}
	end := time.Now()
	fmt.Println(end.Sub(start))
	return nil
}

//go test -run=xxx -bench=.
func BenchmarkCacheHeightLimit233(b *testing.B) {
	db, err := sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/map?maxAllowedPacket=1073741824")
	if err != nil {
		panic(err)
	}

	smt, err := NewSMT(nil, Hasher, db)
	if err != nil {
		panic(err)
	}

	smt.CacheHeightLimit = 233
	keys, values := benchmark1MAccounts(smt, b)
	err = benchmarkGet1MProof(smt, keys, values)
	if err != nil {
		panic(err)
	}

	db.Close()
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
