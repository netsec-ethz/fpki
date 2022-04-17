package main

import (
	DomainOwner "DomainOwner.FPKI.github.com"
	PCA "PCA.FPKI.github.com"
	common "common.FPKI.github.com"
	"testing"
	"time"
)

func Test_RCSR_Verification_With_Correct_Signature(t *testing.T) {
	domainOwner := DomainOwner.DomainOwner{}
	rcsr, err := domainOwner.GenerateRCSR("fpki.com", 1)
	pca := PCA.PCA{}
	pca.InitPCA("testCA", "/Users/yongzhe/Desktop/FPKI/cert/PCACert/server_key.pem")
	err = common.VerifyRCSR(&rcsr)

	if err != nil {
		t.Errorf(err.Error())
	}
}

func Test_RCSR_Verification_With_Wrong_Signature_1(t *testing.T) {
	domainOwner := DomainOwner.DomainOwner{}
	rcsr, err := domainOwner.GenerateRCSR("fpki.com", 1)
	rcsr.Signature = rcsr.Signature[1:]

	pca := PCA.PCA{}
	pca.InitPCA("testCA", "/Users/yongzhe/Desktop/FPKI/cert/PCACert/server_key.pem")
	err = common.VerifyRCSR(&rcsr)

	if err == nil {
		t.Errorf("Error: verification passes with wrong signature")
	}
}

func Test_RCSR_Verification_With_Wrong_Signature_2(t *testing.T) {
	domainOwner := DomainOwner.DomainOwner{}
	rcsr, err := domainOwner.GenerateRCSR("fpki.com", 1)
	rcsr.Signature = append(rcsr.Signature[1:], 'a')

	pca := PCA.PCA{}
	pca.InitPCA("testCA", "/Users/yongzhe/Desktop/FPKI/cert/PCACert/server_key.pem")
	err = common.VerifyRCSR(&rcsr)

	if err == nil {
		t.Errorf("Error: verification passes with wrong signature")
	}
}

func Test_Cool_Off_Period_Logic(t *testing.T) {
	// init domain owner
	domainOwner := DomainOwner.DomainOwner{}

	// init PCA
	pca := PCA.PCA{}
	err := pca.InitPCA("testPCA", "/Users/yongzhe/Desktop/FPKI/cert/PCACert/server_key.pem")
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
		t.Errorf("first rcsr error: shoud not have RPCSignature")
		return
	}

	// sign and log the first rcsr
	err = pca.SignAndLogRCSR(&rcsr)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	// manually generate SPT
	spt1 := &common.SPT{
		Subject: "fpki.com",
	}
	spts := []*common.SPT{spt1}
	pca.ReceiveSPTFromPolicyLog(spts)

	rpc, err := pca.GetNewlyLoggedRPC("fpki.com")
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	// test if the not before of first rpc is correct
	if !rpc.NotBefore.After(time.Now().AddDate(0, 0, 6)) {
		t.Errorf("first rpc's date is wrong")
		return
	}

	// second
	rcsr, err = domainOwner.GenerateRCSR("fpki.com", 1)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	if len(rcsr.PRCSignature) == 0 {
		t.Errorf("second rcsr error: shoud have RPCSignature")
		return
	}

	// sign and log the first rcsr
	err = pca.SignAndLogRCSR(&rcsr)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	// manually generate SPT
	spt1 = &common.SPT{
		Subject: "fpki.com",
	}
	spts = []*common.SPT{spt1}
	pca.ReceiveSPTFromPolicyLog(spts)

	rpc, err = pca.GetNewlyLoggedRPC("fpki.com")
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	// test if the not before of first rpc is correct
	if rpc.NotBefore.After(time.Now().AddDate(0, 0, 6)) {
		t.Errorf("second rpc's date is wrong")
		return
	}

}
