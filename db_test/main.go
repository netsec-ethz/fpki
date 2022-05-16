package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/netsec-ethz/fpki/pkg/db"
)

func main() {
	truncateFlag := flag.Bool("truncate", false, "insert values")
	insertFlag := flag.Bool("insert", false, "insert values")
	queryFlag := flag.Bool("query", false, "perform a query")
	flag.Parse()

	c, err := db.Connect()
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
		t0, err = db.DeletemeSelectLeavesStoredFunc2(1000*1000+192, 16, 16) // 21.987717762s
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
