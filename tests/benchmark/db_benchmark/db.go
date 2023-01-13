package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strconv"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
)

func main() {
	db.TruncateAllTablesWithoutTestObject()
	// *****************************************************************
	//                     open a db connection
	// *****************************************************************

	conn, err := db.Connect(nil)
	if err != nil {
		panic(err)
	}

	// *****************************************************************
	//                     insert 1M node first
	// *****************************************************************
	for i := 0; i < 100; i++ {
		newKVPair := getKeyValuePair(i*45000, i*45000+49999, generateRandomBytes())
		ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
		defer cancelF()
		start := time.Now()
		_, err = conn.UpdateTreeNodes(ctx, newKVPair)
		if err != nil {
			panic(err)
		}

		end := time.Now()
		fmt.Println("iteration ", i, " current iteration: ", i, ", time ", end.Sub(start))
	}

	// *****************************************************************
	//                     read one value, single-threaded
	// *****************************************************************
	for i := 0; i < 100; i++ {
		keys := getKeys(i*1000, i*1000+999)
		ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
		defer cancelF()
		start := time.Now()
		for _, k := range keys {
			value, err := conn.RetrieveTreeNode(ctx, k)
			if err != nil {
				panic(err)
			}
			if value == nil {
				panic("no result")
			}
		}
		end := time.Now()
		fmt.Println("Single-thread READ for 1000 read: index: ", i*1000, "time: ", end.Sub(start))
	}

	// *****************************************************************
	//                     delete entries
	// *****************************************************************
	for i := 0; i < 1000; i++ {
		ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
		defer cancelF()

		keys := getKeys(i*1000, i*1000+999)

		start := time.Now()
		_, err := conn.DeleteTreeNodes(ctx, keys)
		if err != nil {
			panic(err)
		}

		end := time.Now()
		fmt.Println("DELETE ", i*1000, "time ", end.Sub(start))
	}
}

func generateRandomBytes() []byte {
	token := make([]byte, 1024*10)
	rand.Read(token)
	return token
}

func getRandomKeys() []string {
	result := []string{}
	for i := 0; i < 1000; i++ {
		keyHash := common.SHA256Hash([]byte(strconv.Itoa(rand.Intn(900000))))
		keyString := hex.EncodeToString(keyHash)
		result = append(result, keyString)
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

func getKeyValuePair(startIdx, endIdx int, content []byte) []*db.KeyValuePair {
	result := []*db.KeyValuePair{}
	for i := startIdx; i <= endIdx; i++ {
		keyHash := common.SHA256Hash([]byte(strconv.Itoa(i)))
		keyHash32Bytes := [32]byte{}
		copy(keyHash32Bytes[:], keyHash)
		result = append(result, &db.KeyValuePair{Key: keyHash32Bytes, Value: content})
	}
	return result
}

func getRandomIndex(min, max int) []int {
	result := make(map[int]struct{})
	for len(result) < 5000 {
		newRand := rand.Intn(max-min) + min
		result[newRand] = struct{}{}
	}

	resultList := []int{}
	for k := range result {
		resultList = append(resultList, k)
	}
	return resultList
}
