package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"runtime"
	"sort"
	"time"

	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
)

func main() {
	BenchmarkCacheHeightLimit233()
	fmt.Println("bench mark for 300,000 updating and fetching finished")
}

func benchmark10MAccounts10Ktps(smt *trie.Trie) ([][]byte, [][]byte) {
	allKeys := [][]byte{}
	allValues := [][]byte{}
	for i := 0; i < 500; i++ {
		newkeys := getFreshData(100000, 32)
		newvalues := getFreshData(100000, 32)
		allKeys = append(allKeys, newkeys...)
		allValues = append(allValues, newvalues...)

		start := time.Now()
		smt.Update(newkeys, newvalues)
		end := time.Now()
		err := smt.Commit()
		if err != nil {
			panic(err)
		}
		end2 := time.Now()
		for j, key := range newkeys {
			val, _ := smt.Get(key)
			if !bytes.Equal(val, newvalues[j]) {
				panic("new key not included")
			}
		}
		end3 := time.Now()
		elapsed := end.Sub(start)
		elapsed2 := end2.Sub(end)
		elapsed3 := end3.Sub(end2)
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		fmt.Println(i, " : update time : ", elapsed, "commit time : ", elapsed2,
			"\n1000 Get time : ", elapsed3,
			"\ndb read : ", smt.LoadDbCounter, "    cache read : ", smt.LoadCacheCounter,
			"\ncache size : ", smt.GetLiveCacheSize(),
			"\nRAM : ", m.Sys/1024/1024, " MiB")
	}
	return allKeys, allValues
}

//go test -run=xxx -bench=BenchmarkCacheHeightLimit233
func BenchmarkCacheHeightLimit233() {
	conn, err := db.Connect_old()
	if err != nil {
		panic(err)
	}

	smt, err := trie.NewTrie(nil, trie.Hasher, conn)
	if err != nil {
		panic(err)
	}

	smt.CacheHeightLimit = 233
	allKeys, allValues := benchmark10MAccounts10Ktps(smt)
	//benchmark10MAccounts10Ktps(smt, b)

	fmt.Println("length of keys: ", len(allKeys))

	for i := 0; i < 300; i++ {
		start := time.Now()
		for j := 0; j < 1000; j++ {
			ap_, _, _, _, _ := smt.MerkleProof(allKeys[i*10000+j])

			if !trie.VerifyInclusion(smt.Root, ap_, allKeys[i*10000+j], allValues[i*10000+j]) {
				panic("failed to verify inclusion proof")
			}
		}
		end := time.Now()
		fmt.Println("batch ", i, " passed time: ", end.Sub(start))
	}
}

func getFreshData(size, length int) [][]byte {
	var data [][]byte
	for i := 0; i < size; i++ {
		key := make([]byte, 32)
		_, err := rand.Read(key)
		if err != nil {
			panic(err)
		}
		data = append(data, trie.Hasher(key)[:length])
	}
	sort.Sort(trie.DataArray(data))
	return data
}
