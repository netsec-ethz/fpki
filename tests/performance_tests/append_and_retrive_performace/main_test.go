package main

import (
	"context"
	"fmt"
	PL_LogClient "github.com/netsec-ethz/fpki/pkg/policylog/client"
	"math/rand"
	"testing"
	"time"
)

// TODO: modify this later
func Test_Create_Tree_Add_Leaf_Then_Verify_With_Consistency_Proof(t *testing.T) {
	// init admin client
	client, err := PL_LogClient.PL_GetAdminClient("../../../config/policylog/adminclient_config")

	if err != nil {
		t.Errorf(err.Error())
		return
	}

	// create new tree
	tree, err := client.CreateNewTree()
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	// init log client
	logClient, err := PL_LogClient.PL_NewLogClient("../../../config/policyLog/logclient_config", tree.TreeId)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	// add 2000 leaves
	leaves := [][]byte{}
	for i := 1; i < 100; i++ {
		leaves = append(leaves, generateRandomBytes())
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(1000))
	defer cancel()

	start := time.Now()

	addLeavesResult := logClient.AddLeaves(ctx, leaves)
	if len(addLeavesResult.Errs) != 0 {
		t.Errorf("add leaves error")
		fmt.Println(addLeavesResult.Errs)
		return
	}

	elapsed := time.Since(start)
	fmt.Println("queue leaves succeed!")
	fmt.Println(elapsed)

	time.Sleep(2000 * time.Millisecond)

	err = logClient.UpdateTreeSize(ctx)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	start = time.Now()

	incResult := logClient.FetchInclusions(ctx, leaves)

	if len(incResult.Errs) != 0 {
		t.Errorf("fetch inclusion error")
		fmt.Println(incResult.Errs)
		return
	}

	elapsed = time.Since(start)
	fmt.Println("fetch proofs succeed!")
	fmt.Println(elapsed)
}

func generateRandomBytes() []byte {
	token := make([]byte, 300)
	rand.Read(token)
	return token
}
