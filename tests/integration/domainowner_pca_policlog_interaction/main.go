package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/netsec-ethz/fpki/pkg/domainowner"
	"github.com/netsec-ethz/fpki/pkg/logverifier"
	PCA "github.com/netsec-ethz/fpki/pkg/pca"
	"github.com/netsec-ethz/fpki/pkg/policylog/client"
)

// TestPCAPolicyLog: Domain owner generate RCSR -> PCA sign RCSR and send RPC to policy log ->
// Policy log adds the RPC, and return SPT -> PCA receives SPT and verifies the SPT
func main() {
	flag.Parse()
	prepareTestFolder()

	// init domain owner
	do := domainowner.DomainOwner{}

	// new PCA
	pca, err := PCA.NewPCA("./config/pca_config.json")
	if err != nil {
		panic(err)
	}

	// first rcsr
	rcsr, err := do.GenerateRCSR("abc.com", 1)
	if err != nil {
		panic(err)
	}

	if len(rcsr.PRCSignature) != 0 {
		panic("first rcsr error: should not have RPCSignature")
	}

	// sign and log the first rcsr
	err = pca.SignAndLogRCSR(rcsr)
	if err != nil {
		panic(err)
	}

	// second rcsr
	rcsr, err = do.GenerateRCSR("fpki.com", 1)
	if err != nil {
		panic(err)
	}

	// sign and log the second rcsr
	err = pca.SignAndLogRCSR(rcsr)
	if err != nil {
		panic(err)
	}

	adminClient, err := client.GetAdminClient("./config/adminclient_config.json")
	if err != nil {
		panic(err)
	}

	// create new tree
	tree, err := adminClient.CreateNewTree()
	if err != nil {
		panic(err)
	}

	// init log client
	logClient, err := client.NewLogClient("./config/logclient_config.json", tree.TreeId)
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(100))
	defer cancel()

	// queue RPC
	result, err := logClient.QueueRPCs(ctx)
	if err != nil {
		panic(err)
	}

	if len(result.AddLeavesErrs) != 0 || len(result.RetrieveLeavesErrs) != 0 {
		panic("queue error")
	}

	// read SPT and verify
	err = pca.ReceiveSPTFromPolicyLog()
	if err != nil {
		panic(err)
	}

	fileNames, err := ioutil.ReadDir("./file_exchange/rpc")
	if err != nil {
		panic(err)
	}

	if len(fileNames) != 0 {
		panic("rpc num error")
	}

	fileNames, err = ioutil.ReadDir("./file_exchange/spt")
	if err != nil {
		panic(err)
	}

	if len(fileNames) != 0 {
		panic("spt num error")
	}

	os.RemoveAll("./file_exchange")

	verifier := logverifier.NewLogVerifier(nil)

	rpcs := pca.ReturnValidRPC()

	for _, rpcWithSPT := range rpcs {
		err = verifier.VerifyRPC(rpcWithSPT)
		if err != nil {
			panic(err)
		}
	}
	fmt.Println("test succeed!")
}

func prepareTestFolder() {
	err := os.MkdirAll("./file_exchange", os.ModePerm)
	if err != nil {
		panic(err)
	}

	err = os.MkdirAll("./file_exchange/rpc", os.ModePerm)
	if err != nil {
		panic(err)
	}

	err = os.MkdirAll("./file_exchange/spt", os.ModePerm)
	if err != nil {
		panic(err)
	}

	err = os.MkdirAll("./file_exchange/policylog/trees_config", os.ModePerm)
	if err != nil {
		panic(err)
	}
}
