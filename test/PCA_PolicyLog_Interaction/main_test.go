package main

import (
	DomainOwner "DomainOwner.FPKI.github.com"
	PCA "PCA.FPKI.github.com"
	PL_LogClient "PL_LogClient.FPKI.github.com"
	//PL_LogVerifier "PL_LogVerifier.FPKI.github.com"
	//	"bytes"
	//	common "common.FPKI.github.com"
	//	"crypto/rand"
	//	"crypto/rsa"
	"context"
	"testing"
	"time"
)

//------------------------------------------------------
//           tests for structure.go
//------------------------------------------------------
func Test_PCA_PolocyLog(t *testing.T) {

	// init domain owner
	domainOwner := DomainOwner.DomainOwner{}

	// init PCA
	pca := PCA.PCA{}
	err := pca.InitPCA("testPCA", "/Users/yongzhe/Desktop/FPKI/cert/PCACert/server_key.pem", "/Users/yongzhe/Desktop/fpki/fileTransfer/PCA", "/Users/yongzhe/Desktop/fpki/fileTransfer/PolicyLog")
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	// first rcsr
	rcsr, err := domainOwner.GenerateRCSR("fpki.com", 1)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	if len(rcsr.PRCSignature) != 0 {
		t.Errorf("first rcsr error: should not have RPCSignature")
		return
	}

	// sign and log the first rcsr
	err = pca.SignAndLogRCSR(&rcsr)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	// second rcsr
	rcsr, err = domainOwner.GenerateRCSR("abcd.com", 1)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	// sign and log the second rcsr
	err = pca.SignAndLogRCSR(&rcsr)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

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

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(100))
	defer cancel()

	err = logClient.QueueRPCs(ctx, []string{"1", "2"})
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	err = pca.ReceiveSPTFromPolicyLog()
	if err != nil {
		t.Errorf(err.Error())
		return
	}

}

/*
	// init admin client

*/
