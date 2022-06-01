package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
)

func main() {
	testKeyValueStore()
	testUpdateTable()
	fmt.Println("succeed")
}

// testUpdateTable: test if RetrieveTableRowsCount return correct number of entries.
// TODO(yongzhe): need to insert some data first
func testUpdateTable() {
	conn, err := db.Connect_old()
	if err != nil {
		panic(err)
	}

	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	numOfUpdates, err := conn.CountUpdates(ctx)
	if err != nil {
		panic(err)
	}

	keys, err := conn.RetrieveUpdatedDomainMultiThread(ctx, 1000)
	fmt.Println(len(keys), " ", numOfUpdates)
	if len(keys) != numOfUpdates {
		fmt.Println(len(keys), " ", numOfUpdates)
		panic("length not equal")
	}

}

// testKeyValueStore: test insert and read, with arbitrary indexes
func testKeyValueStore() {
	conn, err := db.Connect_old()
	if err != nil {
		panic(err)
	}

	newKVPair := getKeyValuePair(1511, 2012, []byte("hi this is a test"))
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	// update key-value pair from 1511 to 2012
	err, _ = conn.UpdateKeyValues(ctx, newKVPair, db.DomainEntries)
	if err != nil {
		panic(err)
	}

	// update key-value pair from 2013 to 2055
	newKVPair = getKeyValuePair(2013, 2055, []byte("hi this is a test"))
	err, _ = conn.UpdateKeyValues(ctx, newKVPair, db.DomainEntries)
	if err != nil {
		panic(err)
	}

	// update key-value pair from 2056 to 2155
	newKVPair = getKeyValuePair(2056, 2155, []byte("hi this is a test"))
	err, _ = conn.UpdateKeyValues(ctx, newKVPair, db.DomainEntries)
	if err != nil {
		panic(err)
	}

	// update key-value pair from 2056 to 4555
	newKVPair = getKeyValuePair(2056, 4555, []byte("hi this is a test"))
	err, _ = conn.UpdateKeyValues(ctx, newKVPair, db.DomainEntries)
	if err != nil {
		panic(err)
	}

	keys := getKeys(1511, 4555)
	keySize := len(keys)

	// retrieve previously stored key-value pairs
	result, err := conn.RetrieveKeyValuePairMultiThread(ctx, keys, 10, db.DomainEntries)
	if err != nil {
		panic(err)
	}
	if len(result) != keySize {
		panic("key size error 1")
	}

	keys = getKeys(1511, 1511)
	keySize = len(keys)

	// test to retrieve only one key
	result, err = conn.RetrieveKeyValuePairMultiThread(ctx, keys, 10, db.DomainEntries)
	if err != nil {
		panic(err)
	}
	if len(result) != keySize {
		panic("key size error 2")
	}

	keys = getKeys(1542, 1673)
	keySize = len(keys)

	// test to retrieve keys
	result, err = conn.RetrieveKeyValuePairMultiThread(ctx, keys, 10, db.DomainEntries)
	if err != nil {
		panic(err)
	}
	if len(result) != keySize {
		panic("key size error 3")
	}

	keys = getKeys(4555, 6000)
	result, err = conn.RetrieveKeyValuePairMultiThread(ctx, keys, 10, db.DomainEntries)
	if err != nil {
		panic(err)
	}
	if len(result) != 1 {
		panic("key size error 4")
	}

	keys = getKeys(4575, 6000)
	result, err = conn.RetrieveKeyValuePairMultiThread(ctx, keys, 10, db.DomainEntries)
	if err != nil {
		panic(err)
	}
	if len(result) != 0 {
		panic("key size error 4")
	}

	keys = getKeys(1511, 2155)

	err = conn.DeleteKeyValues(ctx, keys, db.DomainEntries)
	if err != nil {
		panic(err)
	}

	keys = getKeys(2056, 4555)

	err = conn.DeleteKeyValues(ctx, keys, db.DomainEntries)
	if err != nil {
		panic(err)
	}

	// test for tree table

	newKVPair = getKeyValuePair(1511, 2012, []byte("hi this is a test"))
	ctx, cancelF = context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	err, _ = conn.UpdateKeyValues(ctx, newKVPair, db.Tree)
	if err != nil {
		panic(err)
	}

	newKVPair = getKeyValuePair(2013, 2055, []byte("hi this is a test"))
	err, _ = conn.UpdateKeyValues(ctx, newKVPair, db.Tree)
	if err != nil {
		panic(err)
	}

	newKVPair = getKeyValuePair(2056, 2155, []byte("hi this is a test"))
	err, _ = conn.UpdateKeyValues(ctx, newKVPair, db.Tree)
	if err != nil {
		panic(err)
	}

	newKVPair = getKeyValuePair(2056, 4555, []byte("hi this is a test"))
	err, _ = conn.UpdateKeyValues(ctx, newKVPair, db.Tree)
	if err != nil {
		panic(err)
	}

	keys = getKeys(1511, 4555)
	keySize = len(keys)

	result, err = conn.RetrieveKeyValuePairMultiThread(ctx, keys, 10, db.Tree)
	if err != nil {
		panic(err)
	}
	if len(result) != keySize {
		panic("key size error 1")
	}

	keys = getKeys(1511, 1511)
	keySize = len(keys)

	result, err = conn.RetrieveKeyValuePairMultiThread(ctx, keys, 10, db.Tree)
	if err != nil {
		panic(err)
	}
	if len(result) != keySize {
		panic("key size error 2")
	}

	keys = getKeys(1542, 1673)
	keySize = len(keys)

	result, err = conn.RetrieveKeyValuePairMultiThread(ctx, keys, 10, db.Tree)
	if err != nil {
		panic(err)
	}
	if len(result) != keySize {
		panic("key size error 3")
	}

	keys = getKeys(4555, 6000)
	result, err = conn.RetrieveKeyValuePairMultiThread(ctx, keys, 10, db.Tree)
	if err != nil {
		panic(err)
	}
	if len(result) != 1 {
		panic("key size error 4")
	}

	keys = getKeys(4575, 6000)
	result, err = conn.RetrieveKeyValuePairMultiThread(ctx, keys, 10, db.Tree)
	if err != nil {
		panic(err)
	}
	if len(result) != 0 {
		panic("key size error 4")
	}

	keys = getKeys(1511, 2155)

	err = conn.DeleteKeyValues(ctx, keys, db.Tree)
	if err != nil {
		panic(err)
	}

	keys = getKeys(2056, 4555)

	err = conn.DeleteKeyValues(ctx, keys, db.Tree)
	if err != nil {
		panic(err)
	}

	conn.Close()
}

func getKeyValuePair(startIdx, endIdx int, content []byte) []db.KeyValuePair {
	result := []db.KeyValuePair{}
	for i := startIdx; i <= endIdx; i++ {
		keyHash := trie.Hasher([]byte(strconv.Itoa(i)))
		keyString := hex.EncodeToString(keyHash)
		result = append(result, db.KeyValuePair{Key: keyString, Value: content})
	}
	return result
}

func getKeys(startIdx, endIdx int) []string {
	result := []string{}
	for i := startIdx; i <= endIdx; i++ {
		keyHash := trie.Hasher([]byte(strconv.Itoa(i)))
		keyString := hex.EncodeToString(keyHash)
		result = append(result, keyString)
	}
	return result
}
