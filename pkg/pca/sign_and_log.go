package pca

import (
	"encoding/base64"
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

	pca.increaseSerialNumber()

	// generate pre-RPC (without SPT)
	rpc, err := common.RCSRGenerateRPC(rcsr, time.Now(), pca.serialNumber, pca.rsaKeyPair, pca.caName)
	if err != nil {
		return fmt.Errorf("SignAndLogRCSR | RCSRGenerateRPC | %w", err)
	}

	rpcHash, err := pca.getHashName(rpc)
	if err != nil {
		return fmt.Errorf("SignAndLogRCSR | getHashName | %w", err)
	}

	// add the rpc to preRPC(without SPT)
	pca.preRPCByDomains[rpcHash] = rpc

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
	if err != nil {
		return fmt.Errorf("SignAndLogPSR | findRPCAndVerifyPSR | %w", err)
	}

	pca.increaseSerialNumber()

	sp, err := common.CASignSP(psr, pca.rsaKeyPair, pca.caName, pca.serialNumber)
	if err != nil {
		return fmt.Errorf("SignAndLogPSR | CASignSP | %w", err)
	}

	spHash, err := pca.getHashName(sp)
	if err != nil {
		return fmt.Errorf("SignAndLogRCSR | getHashName | %w", err)
	}

	pca.preSPByDomains[spHash] = sp

	err = pca.sendSPToPolicyLog(sp, strconv.Itoa(sp.SerialNumber))
	if err != nil {
		return fmt.Errorf("SignAndLogPSR | sendSPToPolicyLog | %w", err)
	}

	return nil
}

func (pca *PCA) findRPCAndVerifyPSR(psr *common.PSR) error {
	rpc, ok := pca.validRPCsByDomains[psr.DomainName]
	if !ok {
		return fmt.Errorf("findRPCAndVerifyPSR | validRPCsByDomains | no valid rpc at this moment")
	}

	err := common.VerifyPSRUsingRPC(psr, rpc)
	if err != nil {
		return fmt.Errorf("findRPCAndVerifyPSR | VerifyPSRUsingRPC | %w", err)
	}

	return nil
}

// save file to output dir
func (pca *PCA) sendRPCToPolicyLog(rpc *common.RPC, fileName string) error {
	return common.JsonStructToFile(rpc, pca.policyLogExgPath+"/rpc/"+fileName)
}

// save file to output dir
func (pca *PCA) sendSPToPolicyLog(sp *common.SP, fileName string) error {
	return common.JsonStructToFile(sp, pca.policyLogExgPath+"/sp/"+fileName)
}

func (pca *PCA) getHashName(s interface{}) (string, error) {
	structBytes, err := common.JsonStructToBytes(s)
	if err != nil {
		return "", fmt.Errorf("getHashName | JsonStructToBytes | %w", err)
	}

	bytesHash := pca.logVerifier.HashLeaf([]byte(structBytes))

	// base64 url encode the hashed value, and this will be the file name of SPT
	fileName := base64.URLEncoding.EncodeToString(bytesHash)

	return fileName, nil
}
