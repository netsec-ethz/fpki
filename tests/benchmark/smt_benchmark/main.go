package main

import (
	"context"
	"crypto/rand"
	"encoding/csv"
	"fmt"
	"os"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
	"github.com/netsec-ethz/fpki/pkg/tests/testdb"
)

var wg sync.WaitGroup

// benchmark for sparse merkle tree
func main() {
	testdb.TruncateAllTablesWithoutTestObject()

	conn, err := db.Connect(nil)
	if err != nil {
		panic(err)
	}

	smt, err := trie.NewTrie(nil, common.SHA256Hash, conn)
	if err != nil {
		panic(err)
	}

	smt.CacheHeightLimit = 200

	csvFile, err := os.Create("smt_update.csv")

	if err != nil {
		panic(err)
	}

	csvwriter := csv.NewWriter(csvFile)

	proof_csvFile, err := os.Create("smt_proof.csv")

	if err != nil {
		panic(err)
	}

	proof_csvwriter := csv.NewWriter(proof_csvFile)

	benchmark10MAccounts10Ktps(smt, csvwriter, proof_csvwriter)

}

func benchmark10MAccounts10Ktps(smt *trie.Trie, update_writer *csv.Writer, proof_writer *csv.Writer) {
	for i := 0; i < 50; i++ {
		fmt.Println("Iteration ", i, " ------------------------------")
		ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
		defer cancelF()

		newKeys := getFreshData(100000, 32)
		newValues := getFreshData(100000, 32)

		start := time.Now()
		smt.Update(ctx, newKeys, newValues)
		end := time.Now()

		err := smt.Commit(ctx)
		if err != nil {
			panic(err)
		}
		end2 := time.Now()

		elapsed := end.Sub(start)
		elapsed2 := end2.Sub(end)

		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		fmt.Println("update time for 100,000 leaves in memory: ", elapsed,
			"\ntime to commit changes to db : ", elapsed2,
			"\ncache size : ", smt.GetLiveCacheSize(),
			"\nRAM : ", m.Sys/1024/1024, " MiB")
		fmt.Println()
		fmt.Println()

		update_writer.Write([]string{elapsed.String(), elapsed2.String()})
		update_writer.Flush()

		benchmark200KProofs(newKeys, smt, proof_writer)
	}
}

func benchmark200KProofs(allKeys [][]byte, smt *trie.Trie, proof_writer *csv.Writer) {
	fmt.Println("length of keys: ", len(allKeys))

	wg.Add(1000)
	start := time.Now()
	for i := 0; i < 1000; i++ {
		go worker(allKeys[i*100:i*100+99], smt)
	}
	wg.Wait()
	end := time.Now()
	fmt.Println("time to retrieve 100,000 proofs: ", end.Sub(start))
	proof_writer.Write([]string{end.Sub(start).String()})
	proof_writer.Flush()
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
