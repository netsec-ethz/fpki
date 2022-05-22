package main

import (
	"context"
	"encoding/hex"
	"strconv"
	"time"

	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
)

func main() {
	conn, err := db.Connect_old()
	if err != nil {
		panic(err)
	}

	newKVPair := getKeyValuePair(1511, 2012, []byte("hi this is a test"))
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	err, _ = conn.UpdateKeyValuePairBatches(ctx, newKVPair, db.DomainEntries)
	if err != nil {
		panic(err)
	}

	newKVPair = getKeyValuePair(2013, 2055, []byte("hi this is a test"))
	err, _ = conn.UpdateKeyValuePairBatches(ctx, newKVPair, db.DomainEntries)
	if err != nil {
		panic(err)
	}

	newKVPair = getKeyValuePair(2056, 2155, []byte("hi this is a test"))
	err, _ = conn.UpdateKeyValuePairBatches(ctx, newKVPair, db.DomainEntries)
	if err != nil {
		panic(err)
	}

	newKVPair = getKeyValuePair(2056, 4555, []byte("hi this is a test"))
	err, _ = conn.UpdateKeyValuePairBatches(ctx, newKVPair, db.DomainEntries)
	if err != nil {
		panic(err)
	}

	keys := getKeys(1511, 4555)
	keySize := len(keys)

	result, err := conn.RetrieveKeyValuePairMultiThread(ctx, keys, 10, db.DomainEntries)
	if err != nil {
		panic(err)
	}
	if len(result) != keySize {
		panic("key size error 1")
	}

	keys = getKeys(1511, 1511)
	keySize = len(keys)

	result, err = conn.RetrieveKeyValuePairMultiThread(ctx, keys, 10, db.DomainEntries)
	if err != nil {
		panic(err)
	}
	if len(result) != keySize {
		panic("key size error 2")
	}

	keys = getKeys(1542, 1673)
	keySize = len(keys)

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

	err = conn.DeleteKeyValuePairBatches(ctx, keys, db.DomainEntries)
	if err != nil {
		panic(err)
	}

	keys = getKeys(2056, 4555)

	err = conn.DeleteKeyValuePairBatches(ctx, keys, db.DomainEntries)
	if err != nil {
		panic(err)
	}

	// test for tree table

	newKVPair = getKeyValuePair(1511, 2012, []byte("hi this is a test"))
	ctx, cancelF = context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	err, _ = conn.UpdateKeyValuePairBatches(ctx, newKVPair, db.Tree)
	if err != nil {
		panic(err)
	}

	newKVPair = getKeyValuePair(2013, 2055, []byte("hi this is a test"))
	err, _ = conn.UpdateKeyValuePairBatches(ctx, newKVPair, db.Tree)
	if err != nil {
		panic(err)
	}

	newKVPair = getKeyValuePair(2056, 2155, []byte("hi this is a test"))
	err, _ = conn.UpdateKeyValuePairBatches(ctx, newKVPair, db.Tree)
	if err != nil {
		panic(err)
	}

	newKVPair = getKeyValuePair(2056, 4555, []byte("hi this is a test"))
	err, _ = conn.UpdateKeyValuePairBatches(ctx, newKVPair, db.Tree)
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

	err = conn.DeleteKeyValuePairBatches(ctx, keys, db.Tree)
	if err != nil {
		panic(err)
	}

	keys = getKeys(2056, 4555)

	err = conn.DeleteKeyValuePairBatches(ctx, keys, db.Tree)
	if err != nil {
		panic(err)
	}
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
