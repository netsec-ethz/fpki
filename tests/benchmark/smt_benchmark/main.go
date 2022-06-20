package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
)

var wg sync.WaitGroup

// benchmark for sparse merkle tree
func main() {
	db.TruncateAllTablesWithoutTestObject()
	BenchmarkCacheHeightLimit233()
	fmt.Println("benchmark for 5M updating and fetching finished")
}

func benchmark10MAccounts10Ktps(smt *trie.Trie) ([][]byte, [][]byte) {
	allKeys := [][]byte{}
	allValues := [][]byte{}
	for i := 0; i < 50; i++ {
		fmt.Println("Iteration ", i, " ------------------------------")
		ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
		defer cancelF()

		newKeys := getFreshData(100000, 32)
		newValues := getFreshData(100000, 32)
		allKeys = append(allKeys, newKeys...)
		allValues = append(allValues, newValues...)

		start := time.Now()
		smt.Update(ctx, newKeys, newValues)
		end := time.Now()

		err := smt.Commit(ctx)
		if err != nil {
			panic(err)
		}
		end2 := time.Now()
		for j, key := range newKeys {
			val, _ := smt.Get(ctx, key)
			if !bytes.Equal(val, newValues[j]) {
				panic("new key not included")
			}
		}
		end3 := time.Now()
		elapsed := end.Sub(start)
		elapsed2 := end2.Sub(end)
		elapsed3 := end3.Sub(end2)
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		fmt.Println("update time for 100,000 leaves in memory: ", elapsed,
			"\ntime to commit changes to db : ", elapsed2,
			"\nTime to get new keys : ", elapsed3,
			"\ncache size : ", smt.GetLiveCacheSize(),
			"\nRAM : ", m.Sys/1024/1024, " MiB")
		fmt.Println()
		fmt.Println()
	}
	return allKeys, allValues
}

//go test -run=xxx -bench=BenchmarkCacheHeightLimit233
func BenchmarkCacheHeightLimit233() {
	conn, err := db.Connect(nil)
	if err != nil {
		panic(err)
	}

	smt, err := trie.NewTrie(nil, common.SHA256Hash, conn)
	if err != nil {
		panic(err)
	}

	smt.CacheHeightLimit = 233
	allKeys, _ := benchmark10MAccounts10Ktps(smt)
	//benchmark10MAccounts10Ktps(smt, b)

	fmt.Println("length of keys: ", len(allKeys))

	wg.Add(20)
	start := time.Now()
	for i := 0; i < 20; i++ {
		go worker(allKeys[i*10000:i*10000+9999], smt)
	}
	wg.Wait()
	end := time.Now()
	fmt.Println("time to retrieve 200,000 proofs: ", end.Sub(start))
}

func worker(input [][]byte, smt *trie.Trie) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	for _, key := range input {
		_, _, _, _, err := smt.MerkleProof(ctx, key)
		if err != nil {
			panic(err)
		}
	}

	wg.Done()
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
