package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/rand"
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

	// insert 10M node first
	for i := 0; i < 1000; i++ {
		newKVPair := getKeyValuePair(i*1000, i*1000+999, generateRandomBytes())
		ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
		defer cancelF()
		start := time.Now()
		err, _ = conn.UpdateKeyValues_TreeStruc(ctx, newKVPair)
		if err != nil {
			panic(err)
		}

		end := time.Now()
		fmt.Println("iteration ", i, " current nodes: ", i, "k time ", end.Sub(start))
	}

	// read ramdomly
	for i := 0; i < 1000; i++ {
		ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
		defer cancelF()

		keys := getKeys(i*1000, i*1000+999)

		start := time.Now()
		result, err := conn.RetrieveKeyValuePair_TreeStruc(ctx, keys, 10)
		if err != nil {
			panic(err)
		}
		if len(result) != 1000 {
			panic("data missing")
		}
		end := time.Now()
		fmt.Println("READ ", i*1000, "time ", end.Sub(start))
	}

	// read one value, single-threaded
	for i := 0; i < 100; i++ {
		keys := getKeys(i*1000, i*1000+999)
		ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
		defer cancelF()
		start := time.Now()
		for _, k := range keys {

			result, err := conn.RetrieveOneKeyValuePair_TreeStruc(ctx, k)
			if err != nil {
				panic(err)
			}
			if result.Value == nil {
				panic("no result")
			}
		}
		end := time.Now()
		fmt.Println("READ Sequentially", i*1000, "time ", end.Sub(start))
	}

	// delete entries
	for i := 0; i < 1000; i++ {
		ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
		defer cancelF()

		keys := getKeys(i*1000, i*1000+999)

		start := time.Now()
		err := conn.DeleteKeyValues_TreeStruc(ctx, keys)
		if err != nil {
			panic(err)
		}

		end := time.Now()
		fmt.Println("DELETE ", i*1000, "time ", end.Sub(start))
	}

	// read ramdomly; should return nil
	for i := 0; i < 1000; i++ {
		ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
		defer cancelF()

		keys := getKeys(i*1000, i*1000+999)

		start := time.Now()
		result, err := conn.RetrieveKeyValuePair_TreeStruc(ctx, keys, 10)
		if err != nil {
			panic(err)
		}
		if len(result) != 0 {
			panic("read deleted data")
		}
		end := time.Now()
		fmt.Println("READ ", i*1000, "time ", end.Sub(start))
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

func generateRandomBytes() []byte {
	token := make([]byte, 1000)
	rand.Read(token)
	return token
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

func getRandomKeys() []string {
	result := []string{}
	for i := 0; i < 1000; i++ {
		keyHash := trie.Hasher([]byte(strconv.Itoa(rand.Intn(900000))))
		keyString := hex.EncodeToString(keyHash)
		result = append(result, keyString)
	}
	return result
}
