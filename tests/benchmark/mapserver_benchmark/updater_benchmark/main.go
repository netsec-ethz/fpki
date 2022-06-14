package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
)

// collect 1M certs, and update them
func main() {
	{ // truncate tables manually
		db, err := sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/fpki?maxAllowedPacket=1073741824")
		if err != nil {
			panic(err)
		}

		// truncate table
		_, err = db.Exec("TRUNCATE fpki.domainEntries;")
		if err != nil {
			panic(err)
		}

		// truncate table
		_, err = db.Exec("TRUNCATE fpki.tree;")
		if err != nil {
			panic(err)
		}

		// truncate table
		_, err = db.Exec("TRUNCATE fpki.updates;")
		if err != nil {
			panic(err)
		}
		if err = db.Close(); err != nil {
			panic(err)
		}
	}

	// new updater
	mapUpdater, err := updater.NewMapUpdater(nil, 233)
	if err != nil {
		panic(err)
	}
	ctx, cancelF := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancelF()

	// collect 100K certs
	mapUpdater.Fetcher.BatchSize = 10000
	const baseCTSize = 2 * 1000
	const count = 10 * 10000
	mapUpdater.StartFetching("https://ct.googleapis.com/logs/argon2021",
		baseCTSize, baseCTSize+count-1)

	updateStart := time.Now()
	for i := 0; ; i++ {
		fmt.Println()
		fmt.Println()
		fmt.Println(" ---------------------- batch ", i, " ---------------------------")
		start := time.Now()
		n, err := mapUpdater.UpdateNextBatch(ctx)
		if err != nil {
			panic(err)
		}
		if n == 0 {
			break
		}
		fmt.Println("time to update the changes: ", time.Since(start))

		start = time.Now()
		err = mapUpdater.CommitSMTChanges(ctx)
		if err != nil {
			panic(err)
		}
		fmt.Println("time to commit the changes: ", time.Since(start))
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
