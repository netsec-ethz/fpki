package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"math"
	"os"
	"strconv"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
)

var domainCount int

// collect 1M certs, and update them
func main() {

	domainCount = 0
	db.TruncateAllTablesWithoutTestObject()

	csvFile, err := os.Create("result.csv")

	if err != nil {
		panic(err)
	}

	csvwriter := csv.NewWriter(csvFile)

	// new updater
	mapUpdater, err := updater.NewMapUpdater(nil, 233)
	if err != nil {
		panic(err)
	}
	ctx, cancelF := context.WithTimeout(context.Background(), 200*time.Minute)
	defer cancelF()

	// collect 100K certs
	mapUpdater.Fetcher.BatchSize = 40000
	const baseCTSize = 2*1000 + 1600000
	const count = 2000 * 1000
	mapUpdater.StartFetching("https://ct.googleapis.com/logs/argon2021",
		baseCTSize, baseCTSize+count-1)

	updateStart := time.Now()
	names := []string{}
	for i := 0; ; i++ {
		fmt.Println()
		fmt.Println()
		fmt.Println(" ---------------------- batch ", i, " ---------------------------")

		n, timeList, newNames, err, writePair, readPair, smtSize := mapUpdater.UpdateNextBatchReturnTimeList(ctx)
		if err != nil {
			panic(err)
		}
		fmt.Println("number of certs: ", n)
		if n == 0 {
			break
		}

		names = append(names, newNames...)

		start := time.Now()
		err = mapUpdater.CommitSMTChanges(ctx)
		if err != nil {
			panic(err)
		}
		fmt.Println("time to commit the changes: ", time.Since(start))
		timeToUpdateSMT := time.Since(start)

		domainCount = db.GetDomainNamesForTest()
		fmt.Println("total domains: ", domainCount)

		err = csvwriter.Write(append(append([]string{strconv.Itoa(i), timeToUpdateSMT.String()}, timeList...),
			strconv.Itoa(domainCount), strconv.Itoa(countDBWriteSize(writePair)), strconv.Itoa(countDBWriteSize(readPair)), strconv.Itoa(smtSize), strconv.Itoa(len(readPair))))
		if err != nil {
			panic(err)
		}

		csvwriter.Flush()
	}
	fmt.Println("************************ Update finished ******************************")
	fmt.Printf("time to get and update %d certs: %s\n", count, time.Since(updateStart))

	root := mapUpdater.GetRoot()
	err = mapUpdater.Close()
	if err != nil {
		panic(err)
	}

	err = os.WriteFile("root", root, 0644)
	if err != nil {
		panic(err)
	}
}

func getTreeDepth() int {
	treeDepth := int(math.Log2(float64(domainCount)))
	fmt.Println("tree depth before: ", treeDepth)

	return 255 - treeDepth
}

func getUniqueName(names []string) []string {
	uniqueSet := make(map[string]struct{})
	for _, name := range names {
		uniqueSet[name] = struct{}{}
	}

	result := []string{}

	for k := range uniqueSet {
		result = append(result, k)
	}
	return result
}

func checkPoP(input []*common.MapServerResponse) bool {
	for _, pair := range input {
		if pair.PoI.ProofType == common.PoP {
			if len(pair.DomainEntryBytes) == 0 {
				panic("result error")
			}
			return true
		}
	}
	return false
}

func countDBWriteSize(keyValuePairs []*db.KeyValuePair) int {
	totalSize := 0
	for _, pair := range keyValuePairs {
		totalSize = totalSize + len(pair.Value)
		totalSize = totalSize + len(pair.Key)
	}
	return totalSize
}
