package client

import (
	"context"
	b64 "encoding/base64"
	"fmt"
	Logverifier "github.com/netsec-ethz/fpki/pkg/logverifier"
	"math/rand"
	"testing"
	"time"
)

// TODO: modify this later
func Test_Create_Tree_Add_Leaf_Then_Verify_With_Consistency_Proof(t *testing.T) {
	// init admin client
	client, err := PL_GetAdminClient("../../../config/policyLog/adminclient_config")

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
	logClient, err := PL_NewLogClient("../../../config/policyLog/logclient_config", tree.TreeId)
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

	// add leaves
	addLeavesResult := logClient.AddLeaves(ctx, leaves)
	if len(addLeavesResult.Errs) != 0 {
		t.Errorf("add leaves error")
		fmt.Println(addLeavesResult.Errs)
		return
	}

	time.Sleep(2000 * time.Millisecond)
	err = logClient.UpdateTreeSize(ctx)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	fetchResult := logClient.FetchInclusions(ctx, leaves)
	if len(fetchResult.Errs) != 0 {
		t.Errorf("retrive leaves error")
		fmt.Println(fetchResult.Errs)
		return
	}

	fmt.Println(fetchResult.FailedLeaves)

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

	addLeavesResult = logClient.AddLeaves(ctx, leaves)
	if len(addLeavesResult.Errs) != 0 {
		t.Errorf("add leaves error")
		fmt.Println(addLeavesResult.Errs)
		return
	}

	time.Sleep(2000 * time.Millisecond)

	// get new root
	newRoot, err := logClient.GetCurrentLogRoot(ctx)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	consistencyProof, err := logClient.GetConsistencyProof(ctx, oldRoot, newRoot)

	verifier := Logverifier.NewLogVerifier(nil)

	for k, v := range fetchResult.PoIs {
		hashedValue, _ := b64.URLEncoding.DecodeString(k)
		err = verifier.VerifyInclusion_WithPrevLogRoot(&v.STH, newRoot, consistencyProof, hashedValue, v.PoIs)
		if err != nil {
			t.Errorf(err.Error())
			return
		}
	}
}

func generateRandomBytes() []byte {
	token := make([]byte, 40)
	rand.Read(token)
	return token
}
