package main

// import (
// 	"context"
// 	"flag"
// 	"fmt"
// 	"io/ioutil"
// 	"os"
// 	"time"

// 	"github.com/netsec-ethz/fpki/pkg/common"
// 	"github.com/netsec-ethz/fpki/pkg/domainowner"
// 	"github.com/netsec-ethz/fpki/pkg/logverifier"
// 	PCA "github.com/netsec-ethz/fpki/pkg/pca"
// 	"github.com/netsec-ethz/fpki/pkg/policylog/client"
// )

// // TestPCAPolicyLog: Domain owner generate RCSR -> PCA sign RCSR and send RPC to policy log ->
// // Policy log adds the RPC, and return SPT -> PCA receives SPT and verifies the SPT
// func main() {
// 	flag.Parse()
// 	prepareTestFolder()

// 	// init domain owner
// 	do := domainowner.NewDomainOwner()

// 	// new PCA
// 	pca, err := PCA.NewPCA("./config/pca_config.json")
// 	if err != nil {
// 		logErrAndQuit(err)
// 	}

// 	// first rcsr
// 	rcsr, err := do.GeneratePolCertSignRequest("TheIssuer", "abc.com", 1)
// 	if err != nil {
// 		logErrAndQuit(err)
// 	}

// 	if len(rcsr.OwnerSignature) != 0 {
// 		panic("first rcsr error: should not have RPCSignature")
// 	}

// 	// sign and log the first rcsr
// 	err = pca.SignAndLogRequest(rcsr)
// 	if err != nil {
// 		logErrAndQuit(err)
// 	}

// 	// second rcsr
// 	rcsr, err = do.GeneratePolCertSignRequest("TheIssuer", "fpki.com", 1)
// 	if err != nil {
// 		logErrAndQuit(err)
// 	}

// 	// sign and log the second rcsr
// 	err = pca.SignAndLogRequest(rcsr)
// 	if err != nil {
// 		logErrAndQuit(err)
// 	}

// 	adminClient, err := client.GetAdminClient("./config/adminclient_config.json")
// 	if err != nil {
// 		logErrAndQuit(err)
// 	}

// 	// create new tree
// 	tree, err := adminClient.CreateNewTree()
// 	if err != nil {
// 		logErrAndQuit(err)
// 	}

// 	// init log client
// 	logClient, err := client.NewLogClient("./config/logclient_config.json", tree.TreeId)
// 	if err != nil {
// 		logErrAndQuit(err)
// 	}

// 	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(100))
// 	defer cancel()

// 	// queue RPC
// 	result, err := logClient.QueueRPCs(ctx)
// 	if err != nil {
// 		logErrAndQuit(err)
// 	}

// 	if len(result.AddLeavesErrs) != 0 || len(result.RetrieveLeavesErrs) != 0 {
// 		logErrAndQuit(fmt.Errorf("queue error"))
// 	}

// 	// read SPT and verify
// 	err = pca.ReceiveSPTFromPolicyLog()
// 	if err != nil {
// 		logErrAndQuit(err)
// 	}

// 	fileNames, err := ioutil.ReadDir("./file_exchange/rpc")
// 	if err != nil {
// 		logErrAndQuit(err)
// 	}

// 	if len(fileNames) != 0 {
// 		logErrAndQuit(fmt.Errorf("rpc num error"))
// 	}

// 	fileNames, err = ioutil.ReadDir("./file_exchange/spt")
// 	if err != nil {
// 		logErrAndQuit(err)
// 	}

// 	if len(fileNames) != 0 {
// 		logErrAndQuit(err)
// 	}

// 	verifier := logverifier.NewLogVerifier(nil)

// 	rpcs := pca.ReturnValidRPC()

// 	for _, rpcWithSPT := range rpcs {
// 		err = verifier.VerifyRPC(rpcWithSPT)
// 		if err != nil {
// 			logErrAndQuit(err)
// 		}
// 	}

// 	if len(rpcs) != 2 {
// 		logErrAndQuit(fmt.Errorf("rpcs num error"))
// 	}

// 	policy1 := common.PolicyAttributes{
// 		TrustedCA: []string{"swiss CA"},
// 	}

// 	policy2 := common.PolicyAttributes{
// 		TrustedCA: []string{"US CA"},
// 	}

// 	pcsr1, err := do.RandomPolicyCertificate("abc.com", policy1)
// 	if err != nil {
// 		logErrAndQuit(err)
// 	}

// 	pcsr2, err := do.RandomPolicyCertificate("fpki.com", policy2)
// 	if err != nil {
// 		logErrAndQuit(err)
// 	}

// 	err = pca.SignAndLogPolicyCertificate(pcsr1)
// 	if err != nil {
// 		logErrAndQuit(err)
// 	}

// 	err = pca.SignAndLogPolicyCertificate(pcsr2)
// 	if err != nil {
// 		logErrAndQuit(err)
// 	}

// 	// logClient.QueueSPs(ctx)

// 	err = pca.ReceiveSPTFromPolicyLog()
// 	if err != nil {
// 		logErrAndQuit(err)
// 	}

// 	if len(result.AddLeavesErrs) != 0 || len(result.RetrieveLeavesErrs) != 0 {
// 		logErrAndQuit(fmt.Errorf("queue error SP"))
// 	}

// 	err = pca.OutputPolicyCertificate()
// 	if err != nil {
// 		logErrAndQuit(err)
// 	}

// 	fmt.Println("test succeed!")
// 	os.RemoveAll("./file_exchange")
// 	os.RemoveAll("./rpc_and_sp")
// }

// func logErrAndQuit(err error) {
// 	os.RemoveAll("./file_exchange")
// 	os.RemoveAll("./rpc_and_sp")
// 	panic(err)
// }

// func prepareTestFolder() {
// 	err := os.MkdirAll("./file_exchange", os.ModePerm)
// 	if err != nil {
// 		logErrAndQuit(err)
// 	}

// 	err = os.MkdirAll("./file_exchange/rpc", os.ModePerm)
// 	if err != nil {
// 		logErrAndQuit(err)
// 	}

// 	err = os.MkdirAll("./file_exchange/sp", os.ModePerm)
// 	if err != nil {
// 		logErrAndQuit(err)
// 	}

// 	err = os.MkdirAll("./file_exchange/spt", os.ModePerm)
// 	if err != nil {
// 		logErrAndQuit(err)
// 	}

// 	err = os.MkdirAll("./file_exchange/policylog/trees_config", os.ModePerm)
// 	if err != nil {
// 		logErrAndQuit(err)
// 	}

// 	err = os.MkdirAll("./rpc_and_sp", os.ModePerm)
// 	if err != nil {
// 		logErrAndQuit(err)
// 	}
// }
