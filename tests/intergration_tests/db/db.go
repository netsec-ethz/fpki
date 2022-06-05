package main

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"database/sql"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
)

func main() {
	clearTable()
	testKeyValueStore()
	testUpdateTable()
	clearTable()
	fmt.Println("succeed")
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
	_, err = conn.UpdateKeyValuesDomainEntries(ctx, newKVPair)
	if err != nil {
		panic(err)
	}

	// update key-value pair from 2013 to 2055
	newKVPair = getKeyValuePair(2013, 2055, []byte("hi this is a test"))
	_, err = conn.UpdateKeyValuesDomainEntries(ctx, newKVPair)
	if err != nil {
		panic(err)
	}

	// update key-value pair from 2056 to 2155
	newKVPair = getKeyValuePair(2056, 2155, []byte("hi this is a test"))
	_, err = conn.UpdateKeyValuesDomainEntries(ctx, newKVPair)
	if err != nil {
		panic(err)
	}

	// update key-value pair from 2056 to 4555
	newKVPair = getKeyValuePair(2056, 4555, []byte("hi this is a test"))
	_, err = conn.UpdateKeyValuesDomainEntries(ctx, newKVPair)
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
	newKVPair = getKeyValuePair(11511, 12012, []byte("hi this is a test"))
	ctx, cancelF = context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	_, err = conn.UpdateKeyValuesTreeStruc(ctx, newKVPair)
	if err != nil {
		panic(err)
	}

	newKVPair = getKeyValuePair(12013, 12055, []byte("hi this is a test"))
	_, err = conn.UpdateKeyValuesTreeStruc(ctx, newKVPair)
	if err != nil {
		panic(err)
	}

	newKVPair = getKeyValuePair(12056, 12155, []byte("hi this is a test"))
	_, err = conn.UpdateKeyValuesTreeStruc(ctx, newKVPair)
	if err != nil {
		panic(err)
	}

	newKVPair = getKeyValuePair(12056, 14555, []byte("hi this is a test"))
	_, err = conn.UpdateKeyValuesTreeStruc(ctx, newKVPair)
	if err != nil {
		panic(err)
	}

	keys = getKeys(11511, 14555)
	keySize = len(keys)

	result = []db.KeyValuePair{}
	for _, key := range keys {
		newResult, err := conn.RetrieveOneKeyValuePairTreeStruc(ctx, key)
		if err != nil && err != sql.ErrNoRows {
			panic(err)
		}
		if newResult != nil {
			result = append(result, *newResult)
		}
	}

	if len(result) != keySize {
		panic("Tree key size error 1")
	}

	keys = getKeys(11511, 11511)
	keySize = len(keys)

	result = []db.KeyValuePair{}
	for _, key := range keys {
		newResult, err := conn.RetrieveOneKeyValuePairTreeStruc(ctx, key)
		if err != nil && err != sql.ErrNoRows {
			panic(err)
		}
		if newResult != nil {
			result = append(result, *newResult)
		}
	}

	if len(result) != keySize {
		panic("Tree key size error 2")
	}

	keys = getKeys(11542, 11673)
	keySize = len(keys)

	result = []db.KeyValuePair{}
	for _, key := range keys {
		newResult, err := conn.RetrieveOneKeyValuePairTreeStruc(ctx, key)
		if err != nil && err != sql.ErrNoRows {
			panic(err)
		}
		if newResult != nil {
			result = append(result, *newResult)
		}
	}

	if len(result) != keySize {
		panic("Tree key size error 3")
	}

	keys = getKeys(14555, 16000)
	result = []db.KeyValuePair{}
	for _, key := range keys {
		newResult, err := conn.RetrieveOneKeyValuePairTreeStruc(ctx, key)
		if err != nil && err != sql.ErrNoRows {
			panic(err)
		}
		if newResult != nil {
			result = append(result, *newResult)
		}
	}

	if len(result) != 1 {
		panic("Tree key size error 4")
	}

	keys = getKeys(14575, 16000)
	result = []db.KeyValuePair{}
	for _, key := range keys {
		newResult, err := conn.RetrieveOneKeyValuePairTreeStruc(ctx, key)
		if err != nil && err != sql.ErrNoRows {
			panic(err)
		}
		if newResult != nil {
			result = append(result, *newResult)
		}
	}

	if len(result) != 0 {
		panic("Tree key size error 5")
	}

	keys = getKeys(11511, 12155)

	_, err = conn.DeleteKeyValuesTreeStruc(ctx, keys)
	if err != nil {
		panic(err)
	}

	keys = getKeys(12056, 14555)

	_, err = conn.DeleteKeyValuesTreeStruc(ctx, keys)
	if err != nil {
		panic(err)
	}

	conn.Close()
}

// testUpdateTable: test if RetrieveTableRowsCount return correct number of entries.
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

	keys := getKeys(100, 200)
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	_, err = conn.AddUpdatedDomainHashesUpdates(ctx, keys)
	if err != nil {
		panic(err)
	}

	newKeys := getKeys(333, 409)
	_, err = conn.AddUpdatedDomainHashesUpdates(ctx, newKeys)
	if err != nil {
		panic(err)
	}

	numOfUpdates, err := conn.GetCountOfUpdatesDomainsUpdates(ctx)
	if err != nil {
		panic(err)
	}

	keys, err = conn.RetrieveUpdatedDomainHashesUpdates(ctx, 1000)
	if len(keys) != numOfUpdates {
		panic("length not equal")
	}

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

func clearTable() {
	db, err := sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/fpki?maxAllowedPacket=1073741824")
	if err != nil {
		panic(err)
	}

	_, err = db.Exec("TRUNCATE domainEntries;")
	if err != nil {
		panic(err)
	}

	_, err = db.Exec("TRUNCATE updates;")
	if err != nil {
		panic(err)
	}

	_, err = db.Exec("TRUNCATE tree;")
	if err != nil {
		panic(err)
	}

}
