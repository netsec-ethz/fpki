package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"sort"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
)

// PLEASE take a look at getFreshData(){}. You need to sort the key-value pairs before adding them to SMT.
// If you want to review the source code, the package is in pkg/mapserver/tire

func main() {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()
	//***************************************************************
	//                    create a new db conn
	//***************************************************************
	dbConn, err := db.Connect(nil)
	if err != nil {
		panic(err)
	}

	//***************************************************************
	//                       get a new SMT
	//***************************************************************
	smt, err := trie.NewTrie(nil, common.SHA256Hash, dbConn)
	if err != nil {
		panic(err)
	}

	// depth of layers which are cached in memory
	// 255 means no cache, and 0 means caching the whole tree in memory
	// used to speed-up the SMT.
	// 0: best performance, but large memory is required(depend on how many leaves you want to cache)
	// num of layer is roughly log_2(num of inserted leaves)
	smt.CacheHeightLimit = 233

	//***************************************************************
	//            update SMT with random key-value pairs
	//***************************************************************
	// Add data to empty SMT
	keys := getFreshData(100, 32)
	values := getFreshData(100, 32)
	smt.Update(ctx, keys, values)

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
	//                   commit changes to db
	//***************************************************************
	err = smt.Commit(ctx)
	if err != nil {
		panic(err)
	}

	//***************************************************************
	//                  create a new db conn
	//***************************************************************
	dbConn1, err := db.Connect(nil)
	if err != nil {
		panic(err)
	}
	//***************************************************************
	//                   start a new SMT
	//***************************************************************
	// NOTE!!!: to load a existing SMT, previous Tree Root is needed
	smt1, err := trie.NewTrie(smt.Root, common.SHA256Hash, dbConn1)

	//***************************************************************
	//                   reload cache
	//***************************************************************
	// Optional. During proof-fetching, library will also gradually load the leaves.
	err = smt1.LoadCache(ctx, smt.Root)
	if err != nil {
		panic(err)
	}

	//***************************************************************
	//                     verify PoP
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
	//                        verify PoA
	//***************************************************************
	emptyKey = common.SHA256Hash([]byte("non-member"))
	ap_, included_, proofKey_, proofValue_, _ = smt1.MerkleProof(ctx, emptyKey)
	if included_ {
		panic("failed to verify new non inclusion proof")
	}
	if !trie.VerifyNonInclusion(smt1.Root, ap_, emptyKey, proofValue_, proofKey_) {
		panic("failed to verify new non inclusion proof")
	}

	//***************************************************************
	//                   delete some key-value pairs
	//***************************************************************
	defaultValues := make([][]byte, 50)
	modifiedKeys := make([][]byte, 50)
	for i := 0; i < 50; i++ {
		defaultValues[i] = []byte{0}
		modifiedKeys[i] = keys[i]
	}

	smt1.Update(ctx, modifiedKeys, defaultValues)

	//***************************************************************
	//                  verify PoA of deleted keys
	//***************************************************************
	for _, key := range modifiedKeys {
		ap, included, proofKey, proofValue, _ := smt1.MerkleProof(ctx, key)
		if included {
			panic("PoP failed")
		}
		if !trie.VerifyNonInclusion(smt1.Root, ap, key, proofValue, proofKey) {
			panic("failed to verify new inclusion proof")
		}
	}

	fmt.Println("succeed!")
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
