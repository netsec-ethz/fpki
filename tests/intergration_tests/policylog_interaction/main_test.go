package main

import (
	"context"
	b64 "encoding/base64"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/netsec-ethz/fpki/pkg/logverifier"
	"github.com/netsec-ethz/fpki/pkg/policylog/client"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//TestCreateTreeAddLeafThenVerifyWithConsistencyProof: add leaves, retrive PoI and STH, then verify the return PoI and STH
func TestCreateTreeAddLeafThenVerifyWithConsistencyProof(t *testing.T) {
	// init admin adminClient
	adminClient, err := client.GetAdminClient("testdata/adminclient_config")
	require.NoError(t, err, "Get admin client error")

	// create new tree
	tree, err := adminClient.CreateNewTree()
	require.NoError(t, err, "Create new tree error")

	// init log client
	logClient, err := client.NewLogClient("testdata/logclient_config", tree.TreeId)
	require.NoError(t, err, "New log client error")

	// add 20 leaves
	leaves := [][]byte{}
	for i := 1; i < 20; i++ {
		leaves = append(leaves, generateRandomBytes())
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(100))
	defer cancel()

	// add leaves
	addLeavesResult := logClient.AddLeaves(ctx, leaves)
	assert.Equal(t, len(addLeavesResult.Errs), 0, "add leaves error")

	time.Sleep(2000 * time.Millisecond)
	err = logClient.UpdateTreeSize(ctx)
	require.NoError(t, err, "Update tree size error")

	fetchResult := logClient.FetchInclusions(ctx, leaves)
	assert.Equal(t, len(fetchResult.Errs), 0, "retrive leaves error")

	fmt.Println(fetchResult.FailedLeaves)

	oldRoot, err := logClient.GetCurrentLogRoot(ctx)
	require.NoError(t, err, "Get current log root error")

	// add another 20 leaves
	leaves = [][]byte{}
	for i := 1; i < 20; i++ {
		leaves = append(leaves, generateRandomBytes())
	}

	addLeavesResult = logClient.AddLeaves(ctx, leaves)
	assert.Equal(t, len(addLeavesResult.Errs), 0, "add leaves error")

	time.Sleep(2000 * time.Millisecond)

	// get new root
	newRoot, err := logClient.GetCurrentLogRoot(ctx)
	require.NoError(t, err, "Get current log root error")

	consistencyProof, err := logClient.GetConsistencyProof(ctx, oldRoot, newRoot)

	verifier := logverifier.NewLogVerifier(nil)

	for k, v := range fetchResult.PoIs {
		hashedValue, _ := b64.URLEncoding.DecodeString(k)
		err = verifier.VerifyInclusionWithPrevLogRoot(&v.STH, newRoot, consistencyProof, hashedValue, v.PoIs)
		require.NoError(t, err, "Verification error")
	}
}

func generateRandomBytes() []byte {
	token := make([]byte, 40)
	rand.Read(token)
	return token
}
