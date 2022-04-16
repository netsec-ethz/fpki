package main

import (
	PL_LogClient "PL_LogClient.FPKI.github.com"
	PL_LogVerifier "PL_LogVerifier.FPKI.github.com"
	"context"
	"fmt"
	"github.com/google/trillian"
	"github.com/transparency-dev/merkle/rfc6962"
	"testing"
	"time"

	"math/rand"
)

func Test_Config(t *testing.T) {
	config := &PL_LogClient.PL_AdminClientConfig{
		RpcMaxWaitingTimeInSec: 10,
		HashStrategy:           trillian.HashStrategy_RFC6962_SHA256.String(),

		// name of the tree
		DisplayName: "policy_log",
		// description of the tree
		Description: "tree for policy log",

		// Interval after which a new signed root is produced despite no submissions; zero means never
		MaxRootDuration: 10,

		MaxReceiveMessageSize: 10000,
		LogAddress:            "localhost:8090",
		OutPutPath:            "/Users/yongzhe/Desktop/fpki/output/trees",
	}

	err := PL_LogClient.SaveConfigToFile(config, "/Users/yongzhe/Desktop/fpki/config/policyLogConfig/adminClientConfig")

	if err != nil {
		t.Errorf(err.Error())
		return
	}

	config_ := &PL_LogClient.PL_AdminClientConfig{}

	PL_LogClient.Json_ReadConfigFromFile(config_, "/Users/yongzhe/Desktop/fpki/config/policyLogConfig/adminClientConfig")
	if !config_.Equal(config) {
		t.Errorf("config Equal() error")
		return
	}
}

func Test_Create_Tree(t *testing.T) {
	client, err := PL_LogClient.PL_GetAdminClient("/Users/yongzhe/Desktop/fpki/config/policyLogConfig/adminClientConfig")

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

func Test_Create_Tree_Add_Leaf_Then_Verify(t *testing.T) {
	// init admin client
	client, err := PL_LogClient.PL_GetAdminClient("/Users/yongzhe/Desktop/fpki/config/policyLogConfig/adminClientConfig")

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
	logClient, err := PL_LogClient.PL_NewLogClient("/Users/yongzhe/Desktop/fpki/config/policyLogConfig/logClientConfig", tree.TreeId)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	// add 20 leaves
	leaves := [][]byte{}
	for i := 1; i < 2000; i++ {
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
	for i := 1; i < 2000; i++ {
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

	consistencyProof, err := logClient.GetConsistencyProof(ctx, oldRoot, newRoot)

	verifier := PL_LogVerifier.NewLogVerifier(nil)

	start := time.Now()
	for k, v := range proofs {

		hashedValue := rfc6962.DefaultHasher.HashLeaf([]byte(k))
		err = verifier.VerifyInclusionByBatch_WithPrevLogRoot(oldRoot, newRoot, consistencyProof, hashedValue, v)
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
*/
