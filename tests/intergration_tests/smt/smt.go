package main

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"fmt"
	"sort"

	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
)

func main() {
	testUpdateWithSameKeys()
	testTrieMerkleProofAndReloadTree()
	testTrieLoadCache()
	fmt.Println("test succeed!")
}

func testUpdateWithSameKeys() {
	db, err := sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/map?multiStatements=true")
	if err != nil {
		panic(err)
	}

	err = dropTestTable(db)
	if err != nil {
		panic(err)
	}

	smt, err := trie.NewTrie(nil, trie.Hasher, db, "deleteTest", true)

	smt.CacheHeightLimit = 0
	// Add 10000 key-value pair
	keys := getFreshData(10000, 32)
	values := getFreshData(10000, 32)
	smt.Update(keys, values)
	err = smt.Commit()
	if err != nil {
		panic(err)
	}

	prevDBSize, err := getDbEntries(db)
	if err != nil {
		panic(err)
	}

	fmt.Println("table size", prevDBSize)

	// get 10000 new values
	newValues := getFreshData(10000, 32)
	smt.Update(keys, newValues)

	err = smt.Commit()
	if err != nil {
		panic(err)
	}

	newDBSize, err := getDbEntries(db)
	if err != nil {
		panic(err)
	}

	fmt.Println("table size", newDBSize)

	if prevDBSize != newDBSize {
		panic("db size not equal")
	}

	smt.Close()
}

func testTrieMerkleProofAndReloadTree() {
	db, err := sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/map?multiStatements=true")
	if err != nil {
		panic(err)
	}

	defer db.Close()
	smt, err := trie.NewTrie(nil, trie.Hasher, db, "cacheStore", true)
	if err != nil {
		panic(err)
	}

	// Add data to empty trie
	keys := getFreshData(100, 32)
	values := getFreshData(100, 32)
	smt.Update(keys, values)
	smt.Commit()

	for i, key := range keys {
		ap, _, k, v, _ := smt.MerkleProof(key)
		if !trie.VerifyInclusion(smt.Root, ap, key, values[i]) {
			panic("failed to verify inclusion proof")
		}
		if !bytes.Equal(key, k) && !bytes.Equal(values[i], v) {
			panic("merkle proof didnt return the correct key-value pair")
		}
	}
	emptyKey := trie.Hasher([]byte("non-memvqbdqwdqwdqber"))
	ap_, included_, proofKey_, proofValue_, _ := smt.MerkleProof(emptyKey)
	if included_ {
		panic("failed to verify non inclusion proof")
	}
	if !trie.VerifyNonInclusion(smt.Root, ap_, emptyKey, proofValue_, proofKey_) {
		panic("failed to verify non inclusion proof")
	}

	db1, err := sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/map?multiStatements=true")
	if err != nil {
		panic(err)
	}

	defer db1.Close()

	smt1, err := trie.NewTrie(smt.Root, trie.Hasher, db1, "cacheStore", true)

	for i, key_ := range keys {
		ap_, _, k_, v_, _ := smt1.MerkleProof(key_)
		if !trie.VerifyInclusion(smt1.Root, ap_, key_, values[i]) {
			panic("failed to verify new inclusion proof")
		}
		if !bytes.Equal(key_, k_) && !bytes.Equal(values[i], v_) {
			panic("new merkle proof didnt return the correct key-value pair")
		}
	}

	emptyKey = trie.Hasher([]byte("non-member"))
	ap_, included_, proofKey_, proofValue_, _ = smt1.MerkleProof(emptyKey)
	if included_ {
		panic("failed to verify new non inclusion proof")
	}
	if !trie.VerifyNonInclusion(smt1.Root, ap_, emptyKey, proofValue_, proofKey_) {
		panic("failed to verify new non inclusion proof")
	}
}

func testTrieLoadCache() {
	db, err := sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/map?multiStatements=true")
	if err != nil {
		panic(err)
	}

	defer db.Close()
	smt, err := trie.NewTrie(nil, trie.Hasher, db, "cacheStore", true)
	if err != nil {
		panic(err)
	}

	// Test size of cache
	smt.CacheHeightLimit = 0
	key0 := make([]byte, 32, 32)
	key1 := make([]byte, 32, 32)
	bitSet(key1, 255)
	values := getFreshData(2, 32)
	smt.Update([][]byte{key0, key1}, values)
	if smt.GetLiveCacheSize() != 66 {
		// the nodes are at the tip, so 64 + 2 = 66
		panic("cache size incorrect")
	}

	// Add data to empty trie
	keys := getFreshData(10, 32)
	values = getFreshData(10, 32)
	smt.Update(keys, values)
	err = smt.Commit()
	if err != nil {
		panic(err)
	}

	// Simulate node restart by deleting and loading cache
	cacheSize := smt.GetLiveCacheSize()
	smt.ResetLiveCache()

	err = smt.LoadCache(smt.Root)

	if err != nil {
		panic(err)
	}
	if cacheSize != smt.GetLiveCacheSize() {
		panic("Cache loading from db incorrect")
	}
}

// get number of rows in the table
func getDbEntries(db *sql.DB) (int, error) {
	queryStr := "SELECT COUNT(*) FROM map.deleteTest;"

	var number int
	err := db.QueryRow(queryStr).Scan(&number)
	if err != nil {
		return 0, fmt.Errorf("getDbEntries | SELECT COUNT(*) | %w", err)
	}

	return number, nil
}

func dropTestTable(db *sql.DB) error {
	queryStr := "DROP TABLE `map`.`deleteTest`;"

	_, err := db.Exec(queryStr)
	if err != nil && err.Error() != "Error 1051: Unknown table 'map.deletetest'" {
		return fmt.Errorf("dropTestTable | DROP | %w", err)
	}

	return nil
}

func getFreshData(size, length int) [][]byte {
	var data [][]byte
	for i := 0; i < size; i++ {
		key := make([]byte, 32)
		_, err := rand.Read(key)
		if err != nil {
			panic(err)
		}
		data = append(data, trie.Hasher(key)[:length])
	}
	sort.Sort(trie.DataArray(data))
	return data
}

func bitSet(bits []byte, i int) {
	bits[i/8] |= 1 << uint(7-i%8)
}
