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
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	updateStart := time.Now()
	// collect 1M certs
	for i := 0; i < 100; i++ {
		fmt.Println()
		fmt.Println()
		fmt.Println(" ---------------------- Iteration ", i, " ---------------------------")
		start := time.Now()
		const baseCTSize = 2 * 1000 * 1000
		err = mapUpdater.UpdateFromCT(ctx, "https://ct.googleapis.com/logs/argon2021",
			baseCTSize+i*10000, baseCTSize+i*10000+10000)
		if err != nil {
			panic(err)
		}
		fmt.Println("time to update the changes: ", time.Since(start))

		start = time.Now()
		err = mapUpdater.CommitSMTChanges(ctx)
		if err != nil {
			panic(err)
		}
		fmt.Println("time to commit the changes: ", time.Since(start))
	}
	updateEnd := time.Now()
	fmt.Println("************************ Update finished ******************************")
	fmt.Println("time to get and update 1,000,000 certs: ", updateEnd.Sub(updateStart))

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
