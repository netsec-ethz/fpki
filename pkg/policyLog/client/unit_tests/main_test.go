package main

import (
	"context"
	b64 "encoding/base64"
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

	// add leaves
	err = logClient.AddLeaves(ctx, leaves)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	time.Sleep(2000 * time.Millisecond)
	err = logClient.UpdateTreeSize(ctx)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	proofs, err := logClient.FetchInclusions(ctx, leaves)

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

	err = logClient.AddLeaves(ctx, leaves)
	if err != nil {
		t.Errorf(err.Error())
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

	verifier := LogVerifier.NewLogVerifier(nil)

	for k, v := range proofs {
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
