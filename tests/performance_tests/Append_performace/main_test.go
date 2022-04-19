package main

import (
	"context"
	"fmt"
	PL_LogClient "logClient.FPKI.github.com"
	"math/rand"
	"testing"
	"time"
)

// TODO: modify this later
func Test_Create_Tree_Add_Leaf_Then_Verify_With_Consistency_Proof(t *testing.T) {
	// init admin client
	client, err := PL_LogClient.PL_GetAdminClient("/Users/yongzhe/Desktop/fpki/config/policyLog/adminClientConfig")

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
	logClient, err := PL_LogClient.PL_NewLogClient("/Users/yongzhe/Desktop/fpki/config/policyLog/logClientConfig", tree.TreeId)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	// add 2000 leaves
	leaves := [][]byte{}
	for i := 1; i < 10000; i++ {
		leaves = append(leaves, generateRandomBytes())
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(1000))
	defer cancel()

	start := time.Now()

	err = logClient.AddLeaves(ctx, leaves)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	elapsed := time.Since(start)
	fmt.Println("queue leaves succeed!")
	fmt.Println(elapsed)

	time.Sleep(5000 * time.Millisecond)

	err = logClient.UpdateTreeSize(ctx)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	start = time.Now()

	_, err = logClient.FetchInclusions(ctx, leaves)
	if err != nil {
		t.Errorf(err.Error())
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

// ------------------------------------------------------------------------------------------
//                                 Deprecated funcs
// ------------------------------------------------------------------------------------------

/*
	leafMsg := []byte("hahahhahahahahhaha")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(10))
	defer cancel()

	proof, err := logClient.AddLeaf(ctx, leafMsg, 1, false)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	fmt.Println(proof)

	leafMsg = []byte("hahahfboahahhaha")
	ctx, cancel = context.WithTimeout(context.Background(), time.Second*time.Duration(10))
	defer cancel()

	proof, err = logClient.AddLeaf(ctx, leafMsg, 2, false)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	fmt.Println(proof)

	ctx, cancel = context.WithTimeout(context.Background(), time.Second*time.Duration(10))
	defer cancel()

	leafMsg = []byte("hahahhahahahahhaha")
	proof, err = logClient.FetchInclusion(ctx, leafMsg, 2)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	ctx, cancel = context.WithTimeout(context.Background(), time.Second*time.Duration(10))
	defer cancel()

	err = logClient.UpdateTreeSize(ctx)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	func Test_Create_Tree(t *testing.T) {
	client, err := PL_LogClient.PL_GetAdminClient("/Users/yongzhe/Desktop/fpki/config/policyLog/adminClientConfig")

	if err != nil {
		t.Errorf(err.Error())
		return
	}

	tree, err := client.CreateNewTree()
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	fmt.Println(tree.TreeId)
}
*/
