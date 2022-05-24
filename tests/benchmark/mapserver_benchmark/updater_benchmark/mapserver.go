package main

import (
	"database/sql"
	"fmt"
	"os"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
)

var wg sync.WaitGroup

func main() {
	db, err := sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/fpki?maxAllowedPacket=1073741824")
	defer db.Close()
	if err != nil {
		panic(err)
	}

	// trancate domain entries table
	_, err = db.Exec("TRUNCATE `fpki`.`domainEntries`;")
	if err != nil {
		panic(err)
	}

	// trancate domain entries table
	_, err = db.Exec("TRUNCATE `fpki`.`tree`;")
	if err != nil {
		panic(err)
	}

	// trancate domain entries table
	_, err = db.Exec("TRUNCATE `fpki`.`updates`;")
	if err != nil {
		panic(err)
	}

	mapUpdater, err := updater.NewMapUpdater(nil, 233)
	if err != nil {
		panic(err)
	}

	updateStart := time.Now()
	for i := 0; i < 100; i++ {
		fmt.Println()
		fmt.Println()
		fmt.Println(" ---------------------- Iteration ", i, " ---------------------------")
		start := time.Now()
		err = mapUpdater.UpdateFromCT("https://ct.googleapis.com/logs/argon2021", int64(2000000+i*10000), int64(2009999+i*10000))
		if err != nil {
			panic(err)
		}
		end := time.Now()
		fmt.Println("time to update the changes: ", end.Sub(start))

		start = time.Now()
		err = mapUpdater.CommitChanges()
		if err != nil {
			panic(err)
		}
		end = time.Now()
		fmt.Println("time to commit the changes: ", end.Sub(start))
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
