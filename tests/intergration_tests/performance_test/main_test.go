package main

import (
	"context"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/netsec-ethz/fpki/pkg/policylog/client"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//TestCreateTreeAddLeafThenGetPoI: Add leaves to tree -> get Proof of Inclusion
// Used to measure the time to add leaves
func TestCreateTreeAddLeafThenGetPoI(t *testing.T) {
	// init admin adminClient
	adminClient, err := client.GetAdminClient("./testdata/adminclient_config")
	require.NoError(t, err, "get admin client error")

	// create new tree
	tree, err := adminClient.CreateNewTree()
	require.NoError(t, err, "create tree error")

	// init log client
	logClient, err := client.NewLogClient("./testdata/logclient_config", tree.TreeId)
	require.NoError(t, err, "new log client error")

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
	assert.Equal(t, len(addLeavesResult.Errs), 0, "add leaves error")

	elapsed := time.Since(start)
	fmt.Println("queue leaves succeed!")
	fmt.Println(elapsed)

	// wait some time for the policy log to actually add the leaves
	// in final implementation, more elegant method is applied.
	time.Sleep(2000 * time.Millisecond)

	// update the tree size of the policy log
	err = logClient.UpdateTreeSize(ctx)
	require.NoError(t, err, "update tree size error")

	start = time.Now()

	// fetch PoI
	incResult := logClient.FetchInclusions(ctx, leaves)
	assert.Equal(t, len(incResult.Errs), 0, "fetch inclusion error")

	elapsed = time.Since(start)
	fmt.Println("fetch proofs succeed!")
	fmt.Println(elapsed)
}

func generateRandomBytes() []byte {
	token := make([]byte, 300)
	rand.Read(token)
	return token
}
