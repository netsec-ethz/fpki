package main

import (
	"context"
	b64 "encoding/base64"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/netsec-ethz/fpki/pkg/logverifier"
	"github.com/netsec-ethz/fpki/pkg/policylog/client"
)

//TestCreateTreeAddLeafThenVerifyWithConsistencyProof: add leaves, retrive PoI and STH, then verify the return PoI and STH
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
	// add 20 leaves
	leaves := [][]byte{}
	for i := 1; i < 20; i++ {
		leaves = append(leaves, generateRandomBytes())
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(100))
	defer cancel()

	// add leaves
	addLeavesResult := logClient.AddLeaves(ctx, leaves)
	if len(addLeavesResult.Errs) != 0 {
		panic("add leaves error")
	}

	time.Sleep(2000 * time.Millisecond)
	err = logClient.UpdateTreeSize(ctx)
	if err != nil {
		panic(err)
	}
	fetchResult := logClient.FetchInclusions(ctx, leaves)
	if len(fetchResult.Errs) != 0 {
		panic("retrive leaves error")
	}

	oldRoot, err := logClient.GetCurrentLogRoot(ctx)
	if err != nil {
		panic(err)
	}
	// add another 20 leaves
	leaves = [][]byte{}
	for i := 1; i < 20; i++ {
		leaves = append(leaves, generateRandomBytes())
	}

	addLeavesResult = logClient.AddLeaves(ctx, leaves)
	if len(addLeavesResult.Errs) != 0 {
		panic("add leaves error")
	}

	time.Sleep(2000 * time.Millisecond)

	// get new root
	newRoot, err := logClient.GetCurrentLogRoot(ctx)
	if err != nil {
		panic(err)
	}
	consistencyProof, err := logClient.GetConsistencyProof(ctx, oldRoot, newRoot)

	verifier := logverifier.NewLogVerifier(nil)

	for k, v := range fetchResult.PoIs {
		hashedValue, _ := b64.URLEncoding.DecodeString(k)
		err = verifier.VerifyInclusionWithPrevLogRoot(&v.STH, newRoot, consistencyProof, hashedValue, v.PoIs)
		if err != nil {
			panic(err)
		}
	}

	os.RemoveAll("./testdata/output")
	fmt.Println("test succeed!")
}

func generateRandomBytes() []byte {
	token := make([]byte, 40)
	rand.Read(token)
	return token
}
