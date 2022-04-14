package main

import (
	DomainOwner "DomainOwner.FPKI.github.com"
	PCA "PCA.FPKI.github.com"
	common "common.FPKI.github.com"
	"fmt"
	spew "github.com/davecgh/go-spew/spew"
	"time"
)

func main() {
	debug := false

	startTime := time.Now()

	// init Domain Owner
	domainOwner := DomainOwner.DomainOwner{}

	rcsr, err := domainOwner.GenerateRCSR("fpki.com", 1)

	// init PCA
	pca := PCA.PCA{}
	err = pca.InitPCA("testPCA", "/Users/yongzhe/Desktop/FPKI/cert/PCACert/server_key.pem")
	if err != nil {
		fmt.Println(err)
		return
	}

	err = pca.SignAndLogRCSR(&rcsr)
	if err != nil {
		fmt.Println(err)
		return
	}

	spt1 := &common.SPT{
		Subject: "fpki.com",
	}
	spts := []*common.SPT{spt1}
	pca.ReceiveSPTFromPolicyLog(spts)

	rpc, err := pca.GetNewlyLoggedRPC("fpki.com")
	if err != nil {
		fmt.Println(err)
		return
	}

	if debug {
		spew.Dump(rpc)
		duration := time.Since(startTime)
		fmt.Println(duration)
	}

	caCert, err := common.X509CertFromFile("/Users/yongzhe/Desktop/FPKI/cert/PCACert/server_cert.pem")
	if err != nil {
		fmt.Println(err)
		return
	}

	err = common.VerifyRPC(caCert, rpc)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("program seems correct")

}
