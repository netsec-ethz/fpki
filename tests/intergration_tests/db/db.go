package main

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
)

func main() {
	testKeyValueStore()
	testUpdateTable()
	fmt.Println("succeed")
}

// testUpdateTable: test if RetrieveTableRowsCount return correct number of entries.
// TODO(yongzhe): need to insert some data first
func testUpdateTable() {
	config := db.Configuration{
		Dsn: "root@tcp(localhost)/fpki",
		Values: map[string]string{
			"interpolateParams": "true", // 1 round trip per query
			"collation":         "binary",
		},
	}
	conn, err := db.Connect(&config)
	if err != nil {
		panic(err)
	}

	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	numOfUpdates, err := conn.GetCountOfUpdatesDomainsUpdates(ctx)
	if err != nil {
		panic(err)
	}

	keys, err := conn.RetrieveUpdatedDomainHashesUpdates(ctx, 1000)
	fmt.Println(len(keys), " ", numOfUpdates)
	if len(keys) != numOfUpdates {
		fmt.Println(len(keys), " ", numOfUpdates)
		panic("length not equal")
	}

}

// testKeyValueStore: test insert and read, with arbitrary indexes
func testKeyValueStore() {
	config := db.Configuration{
		Dsn: "root@tcp(localhost)/fpki",
		Values: map[string]string{
			"interpolateParams": "true", // 1 round trip per query
			"collation":         "binary",
		},
	}
	conn, err := db.Connect(&config)
	if err != nil {
		panic(err)
	}

	newKVPair := getKeyValuePair(1511, 2012, []byte("hi this is a test"))
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	// update key-value pair from 1511 to 2012
	err, _ = conn.UpdateKeyValuesDomainEntries(ctx, newKVPair)
	if err != nil {
		panic(err)
	}

	// update key-value pair from 2013 to 2055
	newKVPair = getKeyValuePair(2013, 2055, []byte("hi this is a test"))
	err, _ = conn.UpdateKeyValuesDomainEntries(ctx, newKVPair)
	if err != nil {
		panic(err)
	}

	// update key-value pair from 2056 to 2155
	newKVPair = getKeyValuePair(2056, 2155, []byte("hi this is a test"))
	err, _ = conn.UpdateKeyValuesDomainEntries(ctx, newKVPair)
	if err != nil {
		panic(err)
	}

	// update key-value pair from 2056 to 4555
	newKVPair = getKeyValuePair(2056, 4555, []byte("hi this is a test"))
	err, _ = conn.UpdateKeyValuesDomainEntries(ctx, newKVPair)
	if err != nil {
		panic(err)
	}

	keys := getKeys(1511, 4555)
	keySize := len(keys)

	// retrieve previously stored key-value pairs
	result, err := conn.RetrieveKeyValuePairDomainEntries(ctx, keys, 10)
	if err != nil {
		panic(err)
	}
	if len(result) != keySize {
		panic("key size error 1")
	}

	keys = getKeys(1511, 1511)
	keySize = len(keys)

	// test to retrieve only one key
	result, err = conn.RetrieveKeyValuePairDomainEntries(ctx, keys, 10)
	if err != nil {
		panic(err)
	}
	if len(result) != keySize {
		panic("key size error 2")
	}

	keys = getKeys(1542, 1673)
	keySize = len(keys)

	// test to retrieve keys
	result, err = conn.RetrieveKeyValuePairDomainEntries(ctx, keys, 10)
	if err != nil {
		panic(err)
	}
	if len(result) != keySize {
		panic("key size error 3")
	}

	keys = getKeys(4555, 6000)
	result, err = conn.RetrieveKeyValuePairDomainEntries(ctx, keys, 10)
	if err != nil {
		panic(err)
	}
	if len(result) != 1 {
		panic("key size error 4")
	}

	keys = getKeys(4575, 6000)
	result, err = conn.RetrieveKeyValuePairDomainEntries(ctx, keys, 10)
	if err != nil {
		panic(err)
	}
	if len(result) != 0 {
		panic("key size error 4")
	}

	keys = getKeys(1511, 2155)

	// test for tree table
	newKVPair = getKeyValuePair(1511, 2012, []byte("hi this is a test"))
	ctx, cancelF = context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	err, _ = conn.UpdateKeyValuesTreeStruc(ctx, newKVPair)
	if err != nil {
		panic(err)
	}

	newKVPair = getKeyValuePair(2013, 2055, []byte("hi this is a test"))
	err, _ = conn.UpdateKeyValuesTreeStruc(ctx, newKVPair)
	if err != nil {
		panic(err)
	}

	newKVPair = getKeyValuePair(2056, 2155, []byte("hi this is a test"))
	err, _ = conn.UpdateKeyValuesTreeStruc(ctx, newKVPair)
	if err != nil {
		panic(err)
	}

	newKVPair = getKeyValuePair(2056, 4555, []byte("hi this is a test"))
	err, _ = conn.UpdateKeyValuesTreeStruc(ctx, newKVPair)
	if err != nil {
		panic(err)
	}

	keys = getKeys(1511, 4555)
	keySize = len(keys)

	result, err = conn.RetrieveKeyValuePairTreeStruc(ctx, keys, 10)
	if err != nil {
		panic(err)
	}
	if len(result) != keySize {
		panic("key size error 1")
	}

	keys = getKeys(1511, 1511)
	keySize = len(keys)

	result, err = conn.RetrieveKeyValuePairTreeStruc(ctx, keys, 10)
	if err != nil {
		panic(err)
	}
	if len(result) != keySize {
		panic("key size error 2")
	}

	keys = getKeys(1542, 1673)
	keySize = len(keys)

	result, err = conn.RetrieveKeyValuePairTreeStruc(ctx, keys, 10)
	if err != nil {
		panic(err)
	}
	if len(result) != keySize {
		panic("key size error 3")
	}

	keys = getKeys(4555, 6000)
	result, err = conn.RetrieveKeyValuePairTreeStruc(ctx, keys, 10)
	if err != nil {
		panic(err)
	}
	if len(result) != 1 {
		panic("key size error 4")
	}

	keys = getKeys(4575, 6000)
	result, err = conn.RetrieveKeyValuePairTreeStruc(ctx, keys, 10)
	if err != nil {
		panic(err)
	}
	if len(result) != 0 {
		panic("key size error 4")
	}

	keys = getKeys(1511, 2155)

	err = conn.DeleteKeyValuesTreeStruc(ctx, keys)
	if err != nil {
		panic(err)
	}

	keys = getKeys(2056, 4555)

	err = conn.DeleteKeyValuesTreeStruc(ctx, keys)
	if err != nil {
		panic(err)
	}

	conn.Close()
}

func getKeyValuePair(startIdx, endIdx int, content []byte) []db.KeyValuePair {
	result := []db.KeyValuePair{}
	for i := startIdx; i <= endIdx; i++ {
		keyHash := common.SHA256Hash([]byte(strconv.Itoa(i)))
		keyHash32Bytes := [32]byte{}
		copy(keyHash32Bytes[:], keyHash)
		result = append(result, db.KeyValuePair{Key: keyHash32Bytes, Value: content})
	}
	return result
}

func getKeys(startIdx, endIdx int) []common.SHA256Output {
	result := []common.SHA256Output{}
	for i := startIdx; i <= endIdx; i++ {
		keyHash := common.SHA256Hash([]byte(strconv.Itoa(i)))
		keyHash32Bytes := [32]byte{}
		copy(keyHash32Bytes[:], keyHash)
		result = append(result, keyHash32Bytes)
	}
	return result
}
