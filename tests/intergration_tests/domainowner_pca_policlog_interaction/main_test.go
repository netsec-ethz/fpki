package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/netsec-ethz/fpki/pkg/domainowner"
	PCA "github.com/netsec-ethz/fpki/pkg/pca"
	"github.com/netsec-ethz/fpki/pkg/policylog/client"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPCAPolocyLog: Domain owner generate RCSR -> PCA sign RCSR and send RPC to policy log ->
// Policy log adds the RPC, and return SPT -> PCA receives SPT and verifies the SPT
func TestPCAPolocyLog(t *testing.T) {
	// init domain owner
	do := domainowner.DomainOwner{}

	// new PCA
	pca, err := PCA.NewPCA("./config/pca/pca_config")
	require.NoError(t, err, "New PCA error")

	// first rcsr
	rcsr, err := do.GenerateRCSR("abc.com", 1)
	require.NoError(t, err, "Generate RCSR for abc.com error")
	assert.Equal(t, len(rcsr.PRCSignature), 0, "first rcsr error: should not have RPCSignature")

	// sign and log the first rcsr
	err = pca.SignAndLogRCSR(rcsr)
	require.NoError(t, err, "Sign and log RCSR for abc.com error")

	// second rcsr
	rcsr, err = do.GenerateRCSR("fpki.com", 1)
	require.NoError(t, err, "Generate RCSR for fpki.com error")

	// sign and log the second rcsr
	err = pca.SignAndLogRCSR(rcsr)
	require.NoError(t, err, "Sign and log RCSR for fpki.com error")

	adminClient, err := client.GetAdminClient("./config/policylog/adminclient_config")
	require.NoError(t, err, "get admin client error")

	// create new tree
	tree, err := adminClient.CreateNewTree()
	require.NoError(t, err, "create new tree error")

	// init log client
	logClient, err := client.NewLogClient("./config/policylog/logclient_config", tree.TreeId)
	require.NoError(t, err, "New log client error")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(100))
	defer cancel()

	// queue RPC
	result, err := logClient.QueueRPCs(ctx, []string{"1", "2"})
	require.NoError(t, err, "Queue RPC error")
	assert.Equal(t, len(result.AddLeavesErrs), 0, "queue error")
	assert.Equal(t, len(result.RetriveLeavesErrs), 0, "queue error")

	fmt.Println(result.NumOfSucceedAddedLeaves, result.NumOfRetrivedLeaves)

	// read SPT and verify
	err = pca.ReceiveSPTFromPolicyLog()
	require.NoError(t, err, "Receive SPT From Policy Log error")
}
