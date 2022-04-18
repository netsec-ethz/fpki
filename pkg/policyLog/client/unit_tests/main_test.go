package main

import (
	"context"
	"fmt"
	"github.com/transparency-dev/merkle/rfc6962"
	PL_LogClient "logClient.FPKI.github.com"
	LogVerifier "logverifier.FPKI.github.com"
	"testing"
	"time"

	"math/rand"
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

	// add 20 leaves
	leaves := [][]byte{}
	for i := 1; i < 20; i++ {
		leaves = append(leaves, generateRandomBytes())
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(100))
	defer cancel()

	proofs, err := logClient.AddLeaves(ctx, leaves, true)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	oldRoot, err := logClient.GetCurrentLogRoot(ctx)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	// add another 20 leaves

	leaves = [][]byte{}
	for i := 1; i < 20; i++ {
		leaves = append(leaves, generateRandomBytes())
	}

	_, err = logClient.AddLeaves(ctx, leaves, true)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	newRoot, err := logClient.GetCurrentLogRoot(ctx)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	_, err = logClient.GetConsistencyProof(ctx, oldRoot, newRoot)

	verifier := LogVerifier.NewLogVerifier(nil)

	start := time.Now()
	for k, v := range proofs {

		fmt.Println(k)
		hashedValue := rfc6962.DefaultHasher.HashLeaf([]byte(k))

		//err = verifier.VerifyInclusionByBatch_WithPrevLogRoot(&v.STH, newRoot, consistencyProof, hashedValue, v.PoIs)
		err = verifier.VerifyInclusionByHash(&v.STH, hashedValue, v.PoIs)
		if err != nil {
			t.Errorf(err.Error())
			return
		}
	}
	elapsed := time.Since(start)
	fmt.Println("verifing leaves succeed!")
	fmt.Println(elapsed)

}

func generateRandomBytes() []byte {
	token := make([]byte, 40)
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
