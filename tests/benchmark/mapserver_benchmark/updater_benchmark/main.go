package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
)

// collect 1M certs, and update them
func main() {
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
	mapUpdater.Fetcher.BatchSize = 10000
	const baseCTSize = 2*1000 + 1600000
	const count = 1000 * 1000
	mapUpdater.StartFetching("https://ct.googleapis.com/logs/argon2021",
		baseCTSize, baseCTSize+count-1)

	updateStart := time.Now()
	for i := 0; ; i++ {
		fmt.Println()
		fmt.Println()
		fmt.Println(" ---------------------- batch ", i, " ---------------------------")
		start := time.Now()
		n, timeList, err := mapUpdater.UpdateNextBatchReturnTimeList(ctx)
		if err != nil {
			panic(err)
		}
		fmt.Println("number of certs: ", n)
		if n == 0 {
			break
		}
		fmt.Println("time to update the changes: ", time.Since(start))
		timeToUpdateChanges := time.Since(start)

		start = time.Now()
		err = mapUpdater.CommitSMTChanges(ctx)
		if err != nil {
			panic(err)
		}
		fmt.Println("time to commit the changes: ", time.Since(start))
		timeToUpdateSMT := time.Since(start)

		err = csvwriter.Write(append([]string{strconv.Itoa(i), timeToUpdateChanges.String(), timeToUpdateSMT.String()}, timeList...))
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
