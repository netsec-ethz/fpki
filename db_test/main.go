package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/netsec-ethz/fpki/pkg/db"
)

func main() {
	insertFlag := flag.Bool("insert", false, "insert values")
	queryFlag := flag.Bool("query", false, "perform a query")
	flag.Parse()

	c, err := db.Connect()
	check(err)
	defer c.Close()

	t0 := time.Now()

	if *insertFlag {
		err = db.DeletemeDropAllNodes(c)
		check(err)
		t0 = time.Now()
		// err = db.DeletemeCreateNodes(c, 1000) // 5.975667276s

		// err = db.DeletemeCreateNodesBulk(c, 1000) // 60.954469ms
		// err = db.DeletemeCreateNodesBulk(c, 1000000) // too slow (before prepared statements)
		// err = db.DeletemeCreateNodesBulk(c, 50000) // 1.724559003s
		// err = db.DeletemeCreateNodesBulk(c, 100000) // too slow

		// err = db.DeletemeCreateNodesBulk2(c, 200000) // 1.161974957s
		// err = db.DeletemeCreateNodesBulk2(c, 1000*1000) // 11.807568854s

		err = db.DeletemeCreateNodesBulk3(c, 1000*1000) // 10.23273209s
	}
	if *queryFlag {
		err = db.DeletemeSelectNodes(c, 1) // 975.161µs
	}

	check(err)
	fmt.Printf("time: %s\n", time.Since(t0))
	fmt.Println("ready")

	// deleteme:

}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
