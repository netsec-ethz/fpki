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
	// insert 50M node first

	for i := 0; i < 10000; i++ {
		newKVPair := getKeyValuePair(i*1000, i*1000+999, generateRandomBytes())
		ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
		defer cancelF()
		start := time.Now()
		err = conn.UpdateKeyValuePairBatches(ctx, newKVPair)
		if err != nil {
			panic(err)
		}

		end := time.Now()
		fmt.Println("iteration ", i, " current nodes: ", i, "k time ", end.Sub(start))
	}

	// read ramdomly
	for i := 0; i < 10000; i++ {
		ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
		defer cancelF()

		keys := getKeys(i*1000, i*1000+999)

		start := time.Now()
		result, err := conn.RetrieveKeyValuePairMultiThread(ctx, keys, 10)
		if err != nil {
			panic(err)
		}
		if len(result.Pairs) != 1000 {
			panic("data missing")
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
		keyHash := trie.Hasher([]byte(strconv.Itoa(rand.Intn(9000000))))
		keyString := hex.EncodeToString(keyHash)
		result = append(result, keyString)
	}
	return result
}
