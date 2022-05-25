package main

import (
	"context"
	"flag"
	"fmt"
	"strconv"
	"time"

	"github.com/netsec-ethz/fpki/pkg/db"
)

func main() {
	truncateFlag := flag.Bool("truncate", false, "insert values")
	insertFlag := flag.Bool("insert", false, "insert values")
	flattenFlag := flag.Bool("flatten", false, "flatten tree to leaves (slow)")
	queryFlag := flag.Bool("query", false, "perform a query")
	testFlag := flag.Bool("test", false, "test insertion parallelism (connCount leavesCount)")
	flag.Parse()

	config := db.Configuration{
		Dsn: "root@tcp(localhost)/fpki",
		Values: map[string]string{
			"interpolateParams": "true", // 1 round trip per query
			"collation":         "binary",
			// "max_sp_recursion_depth": "255", // recursion to build the leaves table
		},
	}
	createConn := func() (db.Conn, error) { // define a function that creates connections
		return db.Connect(&config)
	}

	var err error
	ctx, cancelF := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancelF()
	t0 := time.Now()

	if *truncateFlag {
		c, err := createConn()
		check(err)
		err = db.DeletemeDropAllNodes(c)
		check(err)
		t0 = time.Now()
	}
	if *insertFlag {
		c, err := createConn()
		check(err)
		// err = db.DeletemeCreateNodes2(c, 100*1000)
		// err = db.DeletemeCreateNodes2(c, 1000*1000) // 5m7.557550068s !!!

		// err = db.DeletemeCreateNodes3(c, 100*1000) // 16.733069201s
		// err = db.DeletemeCreateNodes3(c, 1000*1000) // 2m25.8229174156s
		// err = db.DeletemeCreateNodes3(c, 10*1000*1000) //

		// err = db.DeletemeCreateCSV(c, 10) // 0m0.269s
		// err = db.DeletemeCreateCSV(c, 1000) // 73.882003ms
		// err = db.DeletemeCreateCSV(c, 100*1000) // 0m2.386s
		// err = db.DeletemeCreateCSV(c, 1000*1000) // 0m24.743s
		err = db.DeletemeCreateCSV(c, 10*1000*1000) // 7m25.885s
		check(err)
	}
	if *flattenFlag {
		// we need to flatten 500M in 2 hours -> 1M in 14.4 seconds
		// 2^6 = 64 routines in parallel
		// err = db.Flatten(ctx, createConn, 6) // 100K leaves = 0m11.724s
		// err = db.Flatten(ctx, createConn, 6) // 1M leaves = 0m26.616s
		err = db.Flatten(ctx, createConn, 6) // 10M leaves = 6m29.343s
		check(err)
	}
	if *queryFlag {
		// t0, err = db.DeletemeSelectLeavesStoredFunc3(createConn, 100*1000+96, 8, 8) // 3.085243872s
		// t0, err = db.DeletemeSelectLeavesStoredFunc3(createConn, 100*1000+96, 16, 1) // 4.289929758s
		t0, err = db.DeletemeSelectLeavesStoredFunc3(createConn, 100*1000+96, 1, 16) // 4.305125693s
		check(err)
	}
	if *testFlag {
		if flag.NArg() != 2 {
			panic("two integers are required: connectionCount and leavesCount")
		}
		connCount, err := strconv.Atoi(flag.Arg(0))
		if err != nil {
			panic(err)
		}
		leavesCount, err := strconv.Atoi(flag.Arg(1))
		if err != nil {
			panic(err)
		}
		err = db.DeletemeTestInsert(createConn, connCount, leavesCount) // 10M = 0m22.502s
		check(err)
	}
	fmt.Printf("time: %s\n", time.Since(t0))
	fmt.Println("ready")
}

func main2() {
	truncateFlag := flag.Bool("truncate", false, "insert values")
	insertFlag := flag.Bool("insert", false, "insert values")
	queryFlag := flag.Bool("query", false, "perform a query")
	flag.Parse()

	c, err := db.Connect_old()
	check(err)
	defer c.Close()

	t0 := time.Now()

	if *truncateFlag {
		err = db.DeletemeDropAllNodes(c)
		check(err)
		t0 = time.Now()
	}
	if *insertFlag {
		// err = db.DeletemeCreateNodes(c, 1000) // 5.975667276s

		// err = db.DeletemeCreateNodesBulk(c, 1000) // 60.954469ms
		// err = db.DeletemeCreateNodesBulk(c, 1000000) // too slow (before prepared statements)
		// err = db.DeletemeCreateNodesBulk(c, 50000) // 1.724559003s
		// err = db.DeletemeCreateNodesBulk(c, 100000) // too slow

		// err = db.DeletemeCreateNodesBulk2(c, 200000) // 1.161974957s
		// err = db.DeletemeCreateNodesBulk2(c, 1000*1000) // 11.807568854s

		// err = db.DeletemeCreateNodesBulk3(c, 1000*1000) // 10.23273209s

		// err = db.DeletemeCreateNodesBulk4(c, 100*1000) // 1.693980634s
		// err = db.DeletemeCreateNodesBulk4(c, 1000*1000) // 17.182428746s

		// err = db.DeletemeCreateNodes2(c, 1000) // 212.752302ms
		// err = db.DeletemeCreateNodes2(c, 10*1000) // 456.4187ms
		err = db.DeletemeCreateNodes2(c, 100*1000) // 9.51899883s
		// err = db.DeletemeCreateNodes2(c, 100*1000) // 4.351831675s
		// err = db.DeletemeCreateNodes2(c, 1000*1000) // 1m16.537726013s
	}
	if *queryFlag {
		// err = db.DeletemeSelectNodes(c, 1) // 975.161µs
		// err = db.DeletemeSelectNodes(c, 1000) // 108.110884ms
		// err = db.DeletemeSelectNodes(c, 100*1000) // 10.606129185s

		// err = db.DeletemeSelectNodes2(c, 100*1000) // 8.854317991s

		// err = db.DeletemeSelectNodes3(c, 100*1000, 8) // 2.184544624s
		// err = db.DeletemeSelectNodes3(c, 500*1000, 32) // 11.123422821s = 1M in 22.2s

		// err = db.DeletemeSelectNodesRandom4(c, 100*1000, 32) // 2.176723473s
		// err = db.DeletemeSelectNodesRandom4(c, 1000*1000, 16) // 16.294332418s
		// err = db.DeletemeSelectNodesRandom4(c, 1000*1000, 32) // 16.207375911s
		// err = db.DeletemeSelectNodesRandom4(c, 1000*1000, 64) // 16.208407496s

		// t0, err = db.DeletemeSelectNodesRandom5(1000*1000, 16, 2) // 7.190813246s
		// t0, err = db.DeletemeSelectNodesRandom5(1000*1000, 32, 2) // 6.906053331s
		// t0, err = db.DeletemeSelectNodesRandom5(1000*1000+64, 32, 4) // 5.78090823s
		// t0, err = db.DeletemeSelectNodesRandom5(1000*1000+64, 64, 2) // 5.845077626s
		// t0, err = db.DeletemeSelectNodesRandom5(1000*1000+192, 64, 4) // 5.57853586s
		// t0, err = db.DeletemeSelectNodesRandom5(1000*1000+192, 128, 1) // 5.772750195s
		// t0, err = db.DeletemeSelectNodesRandom5(1000*1000+192, 128, 2) // 5.593609741s
		// t0, err = db.DeletemeSelectNodesRandom5(1000*1000+448, 128, 4) // 5.829905885s

		// t0, err = db.DeletemeSelectLeaves(100) // 164.934957ms
		// t0, err = db.DeletemeSelectLeaves(1000) // 1.446072294s
		// t0, err = db.DeletemeSelectLeaves(10 * 1000) // 14.24444017s

		// t0, err = db.DeletemeSelectLeavesStoredProc(1000) // 608.293495ms

		// t0, err = db.DeletemeSelectLeavesStoredFunc(1000) // 459.793285ms
		// t0, err = db.DeletemeSelectLeavesStoredFunc(100 * 1000) // 36.995034654s

		// values at ETH's computer
		// t0, err = db.DeletemeSelectLeavesStoredFunc2(1000, 1, 1) // 373.195752ms
		// t0, err = db.DeletemeSelectLeavesStoredFunc2(1000, 1, 8) // 95.495026ms
		// t0, err = db.DeletemeSelectLeavesStoredFunc2(100*1000, 1, 8) // 8.746812923s
		// t0, err = db.DeletemeSelectLeavesStoredFunc2(100*1000, 1, 16) // 8.096993868s
		// t0, err = db.DeletemeSelectLeavesStoredFunc2(100*1000, 8, 1) // 8.737253918s
		// t0, err = db.DeletemeSelectLeavesStoredFunc2(100*1000+32, 8, 8) // 7.914086447s

		// values at home computer:
		// t0, err = db.DeletemeSelectLeavesStoredFunc2(1000, 1, 1) // 244.728829ms
		// t0, err = db.DeletemeSelectLeavesStoredFunc2(1000, 1, 8) // 55.34648ms
		// t0, err = db.DeletemeSelectLeavesStoredFunc2(100*1000, 1, 8) // 4.77145546s
		// t0, err = db.DeletemeSelectLeavesStoredFunc2(100*1000, 1, 16) // 3.158051082s
		// t0, err = db.DeletemeSelectLeavesStoredFunc2(100*1000, 8, 1) // 4.794854328s
		// t0, err = db.DeletemeSelectLeavesStoredFunc2(100*1000+32, 8, 8) // 2.429056914s
		// t0, err = db.DeletemeSelectLeavesStoredFunc2(1000*1000+192, 16, 16) // 21.987717762s
	}

	check(err)
	fmt.Printf("time: %s\n", time.Since(t0))
	fmt.Println("ready")
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
