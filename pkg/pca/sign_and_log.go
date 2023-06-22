package pca

import (
	"encoding/base64"
	"fmt"
	"strconv"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/common/crypto"
)

// SignAndLogRCSR: sign the rcsr and generate a rpc -> store the rpc to the "fileExchange" folder; policy log will fetch rpc from the folder
func (pca *PCA) SignAndLogRCSR(req *common.PolicyCertificateSigningRequest) error {
	// verify the signature in the rcsr; check if the domain's pub key is correct
	err := crypto.VerifyOwnerSignature(req)
	if err != nil {
		return fmt.Errorf("SignAndLogRCSR | RCSRVerifySignature | %w", err)
	}

	// Set the issuer values from this CA.
	pca.increaseSerialNumber()
	req.Issuer = pca.caName
	req.RawSerialNumber = pca.serialNumber

	// generate pre-RPC (without SPT)
	rpc, err := crypto.SignAsIssuer(req, pca.rsaKeyPair)
	if err != nil {
		return fmt.Errorf("SignAndLogRCSR | RCSRGenerateRPC | %w", err)
	}

	rpcHash, err := pca.getHashName(rpc)
	if err != nil {
		return fmt.Errorf("SignAndLogRCSR | getHashName | %w", err)
	}

	// add the rpc to preRPC(without SPT)
	pca.prePolCertsPerDomain[rpcHash] = rpc

	// send RPC to policy log
	err = pca.sendRPCToPolicyLog(rpc, strconv.Itoa(pca.serialNumber))
	if err != nil {
		return fmt.Errorf("SignAndLogRCSR | sendRPCToPolicyLog | %w", err)
	}

	return nil
}

// SignAndLogPSR: sign and log policy signing request
func (pca *PCA) SignAndLogPolicyCertificate(req *common.PolicyCertificateSigningRequest) error {
	err := pca.findRPCAndVerifyPSR(req)
	if err != nil {
		return fmt.Errorf("SignAndLogPSR | findRPCAndVerifyPSR | %w", err)
	}

	pca.increaseSerialNumber()

	polCert, err := crypto.SignAsIssuer(req, pca.rsaKeyPair)
	if err != nil {
		return fmt.Errorf("SignAndLogPSR | CASignSP | %w", err)
	}

	spHash, err := pca.getHashName(polCert)
	if err != nil {
		return fmt.Errorf("SignAndLogRCSR | getHashName | %w", err)
	}

	pca.prePolCertsPerDomain[spHash] = polCert

	err = pca.sendSPToPolicyLog(polCert, strconv.Itoa(polCert.SerialNumber()))
	if err != nil {
		return fmt.Errorf("SignAndLogPSR | sendSPToPolicyLog | %w", err)
	}

	return nil
}

func (pca *PCA) findRPCAndVerifyPSR(req *common.PolicyCertificateSigningRequest) error {
	rpc, ok := pca.validPolCertsPerDomain[req.Subject()]
	if !ok {
		return fmt.Errorf("findRPCAndVerifyPSR | validRPCsByDomains | no valid rpc at this moment")
	}

	err := crypto.VerifyOwnerSignatureWithPolCert(req, rpc)
	if err != nil {
		return fmt.Errorf("findRPCAndVerifyPSR | VerifyPSRUsingRPC | %w", err)
	}

	return nil
}

// save file to output dir
func (pca *PCA) sendRPCToPolicyLog(rpc *common.PolicyCertificate, fileName string) error {
	return common.ToJSONFile(rpc, pca.policyLogExgPath+"/rpc/"+fileName)
}

// save file to output dir
func (pca *PCA) sendSPToPolicyLog(sp *common.PolicyCertificate, fileName string) error {
	return common.ToJSONFile(sp, pca.policyLogExgPath+"/sp/"+fileName)
}

func (pca *PCA) getHashName(s interface{}) (string, error) {
	structBytes, err := common.ToJSON(s)
	if err != nil {
		return "", fmt.Errorf("getHashName | ToJSON | %w", err)
	}

	bytesHash := pca.logVerifier.HashLeaf([]byte(structBytes))

	// base64 url encode the hashed value, and this will be the file name of SPT
	fileName := base64.URLEncoding.EncodeToString(bytesHash)

	return fileName, nil
}
