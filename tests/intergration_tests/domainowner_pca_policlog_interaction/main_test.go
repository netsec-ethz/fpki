package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	DomainOwner "github.com/netsec-ethz/fpki/pkg/domainowner"
	PCA "github.com/netsec-ethz/fpki/pkg/pca"
	PL_LogClient "github.com/netsec-ethz/fpki/pkg/policylog/client"
)

//------------------------------------------------------
//           tests for structure.go
//------------------------------------------------------
func Test_PCA_PolocyLog(t *testing.T) {

	// init domain owner
	domainOwner := DomainOwner.DomainOwner{}

	// new PCA
	pca, err := PCA.NewPCA("./config/pca/pca_config")
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	// first rcsr
	rcsr, err := domainOwner.GenerateRCSR("abc.com", 1)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	if len(rcsr.PRCSignature) != 0 {
		t.Errorf("first rcsr error: should not have RPCSignature")
		return
	}

	// sign and log the first rcsr
	err = pca.SignAndLogRCSR(rcsr)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	// second rcsr
	rcsr, err = domainOwner.GenerateRCSR("fpki.com", 1)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	// sign and log the second rcsr
	err = pca.SignAndLogRCSR(rcsr)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	client, err := PL_LogClient.PLGetAdminClient("./config/policylog/adminclient_config")

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
	logClient, err := PL_LogClient.PLNewLogClient("./config/policylog/logclient_config", tree.TreeId)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(100))
	defer cancel()

	// queue RPC
	result, err := logClient.QueueRPCs(ctx, []string{"1", "2"})
	if len(result.AddLeavesErrs) != 0 || len(result.RetriveLeavesErrs) != 0 {
		t.Errorf("queue error")
		return
	}

	fmt.Println(result.NumOfSucceedAddedLeaves, result.NumOfRetrivedLeaves)

	if err != nil {
		t.Errorf(err.Error())
		return
	}

	// read SPT and verify
	err = pca.ReceiveSPTFromPolicyLog()
	if err != nil {
		t.Errorf(err.Error())
		return
	}

}
