package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"sort"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
)

func main() {
	truncateTable()
	testUpdateWithSameKeys()
	testTrieMerkleProofAndReloadTree()
	testTrieLoadCache()
	truncateTable()
	fmt.Println("smt test succeed!")
}

// update the db twice, with the same keys but different values
// to check whether db size grows
func testUpdateWithSameKeys() {
	//***************************************************************
	//                     connect to db
	//***************************************************************
	config := db.Configuration{
		Dsn: "root@tcp(localhost)/fpki",
		Values: map[string]string{
			"interpolateParams": "true", // 1 round trip per query
			"collation":         "binary",
		},
	}

	db, err := db.Connect(&config)
	if err != nil {
		panic(err)
	}

	//***************************************************************
	//                    get a new SMT
	//***************************************************************
	smt, err := trie.NewTrie(nil, common.SHA256Hash, db)

	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	smt.CacheHeightLimit = 0
	// Add 10000 key-value pair
	keys := getFreshData(10000, 32)
	values := getFreshData(10000, 32)

	//***************************************************************
	//             update and commit the tree to db
	//***************************************************************
	smt.Update(ctx, keys, values)

	err = smt.Commit(ctx)
	if err != nil {
		panic(err)
	}

	prevDBSize, err := getDbEntries()
	if err != nil {
		panic(err)
	}

	//***************************************************************
	//           update the same key with different values
	//***************************************************************
	// get 10000 new values
	newValues := getFreshData(10000, 32)
	smt.Update(ctx, keys, newValues)

	err = smt.Commit(ctx)
	if err != nil {
		panic(err)
	}

	newDBSize, err := getDbEntries()
	if err != nil {
		panic(err)
	}

	//***************************************************************
	//              check if db size does not change
	//***************************************************************
	if prevDBSize != newDBSize {
		panic("db size not equal")
	}

	err = smt.Close()
	if err != nil {
		panic(err)
	}
}

// update a tree, commit to db, reload the tree, and test proofs
func testTrieMerkleProofAndReloadTree() {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()
	//***************************************************************
	//                     connect to a new db
	//***************************************************************
	config := db.Configuration{
		Dsn: "root@tcp(localhost)/fpki",
		Values: map[string]string{
			"interpolateParams": "true", // 1 round trip per query
			"collation":         "binary",
		},
	}
	dbConn, err := db.Connect(&config)
	if err != nil {
		panic(err)
	}

	//***************************************************************
	//                    get a new SMT
	//***************************************************************
	smt, err := trie.NewTrie(nil, common.SHA256Hash, dbConn)
	if err != nil {
		panic(err)
	}

	// Add data to empty trie
	keys := getFreshData(100, 32)
	values := getFreshData(100, 32)
	smt.Update(ctx, keys, values)

	//***************************************************************
	//                   commit changes to db
	//***************************************************************
	smt.Commit(ctx)

	//***************************************************************
	//          generate Proof of Presence, and verify them
	//***************************************************************
	for i, key := range keys {
		ap, isIncluded, k, v, _ := smt.MerkleProof(ctx, key)
		if !isIncluded {
			panic("proof type error")
		}
		if !trie.VerifyInclusion(smt.Root, ap, key, values[i]) {
			panic("failed to verify inclusion proof")
		}
		if !bytes.Equal(key, k) && !bytes.Equal(values[i], v) {
			panic("merkle proof didn't return the correct key-value pair")
		}
	}

	//***************************************************************
	//          generate Proof of Absence, and verify them
	//***************************************************************
	emptyKey := common.SHA256Hash([]byte("non-memvqbdqwdqwdqber"))
	ap_, included_, proofKey_, proofValue_, _ := smt.MerkleProof(ctx, emptyKey)
	if included_ {
		panic("failed to verify non inclusion proof")
	}
	if !trie.VerifyNonInclusion(smt.Root, ap_, emptyKey, proofValue_, proofKey_) {
		panic("failed to verify non inclusion proof")
	}

	//***************************************************************
	//                          start a new db
	//***************************************************************
	dbConn1, err := db.Connect(&config)
	if err != nil {
		panic(err)
	}
	//***************************************************************
	//                   start a new SMT
	//***************************************************************
	smt1, err := trie.NewTrie(smt.Root, common.SHA256Hash, dbConn1)

	//***************************************************************
	//                   reload cache
	//***************************************************************
	err = smt1.LoadCache(ctx, smt.Root)
	if err != nil {
		panic(err)
	}

	//***************************************************************
	//                   verify PoP
	//***************************************************************
	for i, key_ := range keys {
		ap_, included_, k_, v_, _ := smt1.MerkleProof(ctx, key_)
		if !trie.VerifyInclusion(smt1.Root, ap_, key_, values[i]) {
			panic("failed to verify new inclusion proof")
		}
		if !included_ {
			panic("PoP failed")
		}
		if !bytes.Equal(key_, k_) && !bytes.Equal(values[i], v_) {
			panic("new merkle proof didn't return the correct key-value pair")
		}
	}

	//***************************************************************
	//                   verify PoA
	//***************************************************************
	emptyKey = common.SHA256Hash([]byte("non-member"))
	ap_, included_, proofKey_, proofValue_, _ = smt1.MerkleProof(ctx, emptyKey)
	if included_ {
		panic("failed to verify new non inclusion proof")
	}
	if !trie.VerifyNonInclusion(smt1.Root, ap_, emptyKey, proofValue_, proofKey_) {
		panic("failed to verify new non inclusion proof")
	}

}

func testTrieLoadCache() {
	config := db.Configuration{
		Dsn: "root@tcp(localhost)/fpki",
		Values: map[string]string{
			"interpolateParams": "true", // 1 round trip per query
			"collation":         "binary",
		},
	}
	dbConn, err := db.Connect(&config)
	if err != nil {
		panic(err)
	}

	smt, err := trie.NewTrie(nil, common.SHA256Hash, dbConn)
	if err != nil {
		panic(err)
	}
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	// Test size of cache
	smt.CacheHeightLimit = 0
	key0 := make([]byte, 32, 32)
	key1 := make([]byte, 32, 32)
	bitSet(key1, 255)
	values := getFreshData(2, 32)
	smt.Update(ctx, [][]byte{key0, key1}, values)
	if smt.GetLiveCacheSize() != 66 {
		// the nodes are at the tip, so 64 + 2 = 66
		panic("cache size incorrect")
	}

	// Add data to empty trie
	keys := getFreshData(10, 32)
	values = getFreshData(10, 32)
	smt.Update(ctx, keys, values)

	err = smt.Commit(ctx)
	if err != nil {
		panic(err)
	}

	// Simulate node restart by deleting and loading cache
	cacheSize := smt.GetLiveCacheSize()
	smt.ResetLiveCache()

	err = smt.LoadCache(ctx, smt.Root)
	if err != nil {
		panic(err)
	}

	if cacheSize != smt.GetLiveCacheSize() {
		panic("Cache loading from db incorrect")
	}
}

// get number of rows in the table
func getDbEntries() (int, error) {
	db, err := sql.Open("mysql", "root@tcp(localhost)/fpki")
	if err != nil {
		return 0, fmt.Errorf("getDbEntries | sql.Open | %w", err)
	}
	queryStr := "SELECT COUNT(*) FROM tree;"

	var number int
	err = db.QueryRow(queryStr).Scan(&number)
	if err != nil {
		return 0, fmt.Errorf("getDbEntries | SELECT COUNT(*) | %w", err)
	}

	return number, nil
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
	sort.Sort(trie.DataArray(data))
	return data
}

func bitSet(bits []byte, i int) {
	bits[i/8] |= 1 << uint(7-i%8)
}

func truncateTable() {
	db, err := sql.Open("mysql", "root@tcp(localhost)/fpki")
	if err != nil {
		panic(fmt.Errorf("truncateTable | sql.Open | %w", err))
	}
	queryStr := "TRUNCATE `fpki`.`tree`;"

	_, err = db.Exec(queryStr)
	if err != nil {
		panic(fmt.Errorf("truncateTable |  db.Exec | %w", err))
	}
}
