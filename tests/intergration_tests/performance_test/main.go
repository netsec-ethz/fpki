package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/netsec-ethz/fpki/pkg/policylog/client"
)

//TestCreateTreeAddLeafThenGetPoI: Add leaves to tree -> get Proof of Inclusion
// Used to measure the time to add leaves
func main() {
	flag.Parse()
	err := os.MkdirAll("./file_exchange/policylog/trees_config", os.ModePerm)
	if err != nil {
		panic(err)
	}

	// init admin adminClient
	adminClient, err := client.GetAdminClient("config/adminclient_config.json")
	if err != nil {
		panic(err)
	}

	// create new tree
	tree, err := adminClient.CreateNewTree()
	if err != nil {
		panic(err)
	}

	// init log client
	logClient, err := client.NewLogClient("config/logclient_config.json", tree.TreeId)
	if err != nil {
		panic(err)
	}

	// prepare 20 leaves
	leaves := [][]byte{}
	for i := 1; i < 20; i++ {
		leaves = append(leaves, generateRandomBytes())
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(1000))
	defer cancel()

	start := time.Now()

	// add 20 leaves to log
	addLeavesResult := logClient.AddLeaves(ctx, leaves)
	if len(addLeavesResult.Errs) != 0 {
		panic("add leaves error")
	}

	elapsed := time.Since(start)
	fmt.Println("queue leaves succeed!")
	fmt.Println(elapsed)

	// wait some time for the policy log to actually add the leaves
	// in final implementation, more elegant method is applied.
	time.Sleep(2000 * time.Millisecond)

	// update the tree size of the policy log
	err = logClient.UpdateTreeSize(ctx)
	if err != nil {
		panic(err)
	}

	start = time.Now()

	// fetch PoI
	incResult := logClient.FetchInclusions(ctx, leaves)
	if len(incResult.Errs) != 0 {
		panic("fetch inclusion error")
	}

	elapsed = time.Since(start)
	fmt.Println("fetch proofs succeed!")
	fmt.Println(elapsed)

	os.RemoveAll("./testdata/trees_config")
	fmt.Println("test succeed!")
}

func generateRandomBytes() []byte {
	token := make([]byte, 300)
	rand.Read(token)
	return token
}
