package pca

import (
	"fmt"
	"strconv"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
)

// SignAndLogRCSR: sign the rcsr and generate a rpc -> store the rpc to the "fileExchange" folder; policy log will fetch rpc from the folder
func (pca *PCA) SignAndLogRCSR(rcsr *common.RCSR) error {
	// verify the signature in the rcsr; check if the domain's pub key is correct
	err := common.RCSRVerifySignature(rcsr)
	if err != nil {
		return fmt.Errorf("SignAndLogRCSR | RCSRVerifySignature | %w", err)
	}

	// decide not before time
	notBefore := time.Now()

	pca.increaseSerialNumber()

	// generate pre-RPC (without SPT)
	rpc, err := common.RCSRGenerateRPC(rcsr, notBefore, pca.serialNumber, pca.rsaKeyPair, pca.caName)
	if err != nil {
		return fmt.Errorf("SignAndLogRCSR | RCSRGenerateRPC | %w", err)
	}

	// add the rpc to preRPC(without SPT)
	pca.preRPCByDomains[rpc.SerialNumber] = rpc

	// send RPC to policy log
	err = pca.sendRPCToPolicyLog(rpc, strconv.Itoa(pca.serialNumber))

	if err != nil {
		return fmt.Errorf("SignAndLogRCSR | sendRPCToPolicyLog | %w", err)
	}
	return nil
}

// SignAndLogPSR: sign and log policy signing request
func (pca *PCA) SignAndLogSP(psr *common.PSR) error {
	err := pca.findRPCAndVerifyPSR(psr)
	if err != nil{
		return fmt.Errorf("SignAndLogPSR | findRPCAndVerifyPSR | %w", err)
	}

	pca.increaseSerialNumber()

	newSP := &common.SP{
		Policies: psr.Policies,
		TimeStamp: psr.TimeStamp,
		Subject: psr.DomainName,
		RootCertSignature: psr.RootCertSignature,
		CAName: pca.caName,
		SerialNumber: ,
	}
}

func (pca *PCA)findRPCAndVerifyPSR(psr *common.PSR) error{
	rpc, ok := pca.validRPCsByDomains[psr.DomainName]
	if !ok{
		return fmt.Errorf("findRPCAndVerifyPSR | validRPCsByDomains | no valid rpc at this moment")
	}
	
	err := common.VerifySPUsingRPC(psr, rpc)
	if err != nil{
		return fmt.Errorf("findRPCAndVerifyPSR | VerifySPUsingRPC | %w", err)
	}

	return nil
}
// save file to output dir
func (pca *PCA) sendRPCToPolicyLog(rpc *common.RPC, fileName string) error {
	return common.JsonStrucToFile(rpc, pca.policyLogExgPath+"/rpc/"+fileName)
}

// save file to output dir
func (pca *PCA) sendSPToPolicyLog(rpc *common.SP, fileName string) error {
	return common.JsonStrucToFile(rpc, pca.policyLogExgPath+"/sp/"+fileName)
}
