package pca

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/google/trillian"
	common "github.com/netsec-ethz/fpki/pkg/common"
	logverifier "github.com/netsec-ethz/fpki/pkg/logverifier"
	"log"
	"strconv"
	"time"
)

// TODO: How to handle Cool-off period?
//       SuspeciousSPTs
//       Let domain owner sends the previous RPC (PCA needs to store the RPC anyway, right? If domain owner loses the RPC, PCA can return the missing RPC)
//       More complete logic

type PCA struct {
	caName string

	// pca's signing rsa key pair; used to sign rcsr -> rpc
	rsaKeyPair *rsa.PrivateKey

	// store valid RPC (with SPT) in memory; Later replaced by data base
	validRPCsByDomains map[string]*common.RPC

	// RPC whitout SPT; pre-certificate
	preRPCByDomains map[string]*common.RPC

	// PCA's output path; sends RPC
	outputPath string

	// policy log's output path; receives SPT
	policyLogOutputPath string

	// verifier to verify the STH and PoI
	logVerifier *logverifier.LogVerifier

	// serial number for the RPC; unique for every RPC
	serialNumber int
}

func NewPCA(configPath string) (*PCA, error) {
	pca := &PCA{}

	// read config file
	config := &PCAConfig{}
	err := ReadConfigFromFile(config, configPath)
	if err != nil {
		return nil, fmt.Errorf("NewPCA | LoadRSAKeyPairFromFile | %s", err.Error())
	}

	pca.caName = config.CAName
	pca.outputPath = config.OutputPath
	pca.policyLogOutputPath = config.PolicyLogOutputPath

	// load rsa key pair
	keyPair, err := common.LoadRSAKeyPairFromFile(config.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("NewPCA | LoadRSAKeyPairFromFile | %s", err.Error())
	}
	pca.rsaKeyPair = keyPair

	pca.validRPCsByDomains = make(map[string]*common.RPC)
	pca.preRPCByDomains = make(map[string]*common.RPC)

	pca.serialNumber = 0
	pca.logVerifier = logverifier.NewLogVerifier(nil)

	return pca, nil
}

// sign the rcsr and generate a rpc -> store the rpc to the "fileExchange" folder; policy log will fetch rpc from the folder
func (pca *PCA) SignAndLogRCSR(rcsr *common.RCSR) error {
	// verify the signature in the rcsr; check if the domain's pub key is correct
	err := common.RCSR_VerifySignature(rcsr)
	if err != nil {
		return fmt.Errorf("SignAndLogRCSR | RCSR_VerifySignature | %s", err.Error())
	}

	// decide not before time
	var notBefore time.Time

	// check if the rpc signature comes from valid rpc
	if pca.checkRPCSignature(rcsr) {
		notBefore = time.Now()
	} else {
		// cool off period
		notBefore = time.Now().AddDate(0, 0, 7)
	}

	pca.increaseSerialNumber()

	// generate pre-RPC (without SPT)
	rpc, err := common.RCSR_GenerateRPC(rcsr, notBefore, pca.getSerialNumber(), pca.rsaKeyPair, pca.caName)
	if err != nil {
		return fmt.Errorf("SignAndLogRCSR | RCSR_GenerateRPC | %s", err.Error())
	}

	// add the rpc to preRPC(without SPT)
	pca.preRPCByDomains[rpc.Subject] = rpc

	// send RPC to policy log
	err = pca.sendRPCToPolicyLog(rpc, strconv.Itoa(pca.getSerialNumber()))

	if err != nil {
		return fmt.Errorf("SignAndLogRCSR | sendRPCToPolicyLog | %s", err.Error())
	}

	return nil
}

// When policy log returns SPT, this func will be called
// this func will read the SPTs from the file, and process them
func (pca *PCA) ReceiveSPTFromPolicyLog() error {
	for k, v := range pca.preRPCByDomains {
		rpcBytes, err := common.Json_StrucToBytes(v)
		if err != nil {
			return fmt.Errorf("ReceiveSPTFromPolicyLog | Json_StrucToBytes | %s", err.Error())
		}

		// hash the rpc
		rpcHash := pca.logVerifier.HashLeaf([]byte(rpcBytes))

		// base64 url encode the hashed value, and this will be the file name of SPT
		fileName := base64.URLEncoding.EncodeToString(rpcHash)

		// read the corresponding spt
		spt := &common.SPT{}
		err = common.Json_FileToSPT(spt, pca.policyLogOutputPath+"/spt/"+fileName)
		if err != nil {
			return fmt.Errorf("ReceiveSPTFromPolicyLog | Json_FileToRPC | %s", err.Error())
		}

		// verify the PoI, STH
		err = pca.verifySPT(spt, v)
		if err == nil {
			log.Printf("Get a new SPT for domain: %s\n", k)
			v.SPTs = []common.SPT{*spt}

			// move the rpc from pre-rpc to valid-rpc
			delete(pca.preRPCByDomains, k)
			pca.validRPCsByDomains[k] = v

		} else {
			log.Printf("fail to verify")
			// TODO: change this to soft-fail, or add it the spicious SPT; for testing, we use hard-fail here
			return fmt.Errorf("Fail to verify one SPT")
		}
	}
	return nil
}

// return the new RPC with SPT
func (pca *PCA) GetValidRPCByDomain(domainName string) (*common.RPC, error) {
	if rpc, found := pca.validRPCsByDomains[domainName]; found {
		return rpc, nil
	} else {
		return nil, errors.New("no valid RPC")
	}
}

// verify the SPT of the RPC.
func (pca *PCA) verifySPT(spt *common.SPT, rpc *common.RPC) error {
	// construct proofs
	proofs := []*trillian.Proof{}
	for _, poi := range spt.PoI {
		poiStruc, err := common.Json_BytesToPoI(poi)
		if err != nil {
			return fmt.Errorf("verifySPT | Json_BytesToPoI | %s", err.Error())
		}
		proofs = append(proofs, poiStruc)
	}

	// get leaf hash
	rpcBytes, err := common.Json_StrucToBytes(rpc)
	if err != nil {
		return fmt.Errorf("verifySPT | Json_StrucToBytes | %s", err.Error())
	}
	leafHash := pca.logVerifier.HashLeaf(rpcBytes)

	// get LogRootV1
	logRoot, err := common.Json_BytesToLogRoot(spt.STH)

	// verify the PoI
	err = pca.logVerifier.VerifyInclusionByHash(logRoot, leafHash, proofs)
	return err
}

// TODO: modify this to make sure unique SN
func (pca *PCA) getSerialNumber() int {
	return pca.serialNumber
}

// TODO: modify this to make sure unique SN
func (pca *PCA) increaseSerialNumber() {
	pca.serialNumber = pca.serialNumber + 1
}

// check whether the
func (pca *PCA) checkRPCSignature(rcsr *common.RCSR) bool {
	// if no rpc signature
	if len(rcsr.PRCSignature) == 0 {
		return false
	}

	// check if there is any valid rpc
	if rpc, found := pca.validRPCsByDomains[rcsr.Subject]; found {
		err := common.RCSR_VerifyRPCSIgnature(rcsr, rpc)
		if err == nil {
			return true
		} else {
			return false
		}
	} else {
		return false
	}
}

// save file to output dir
func (pca *PCA) sendRPCToPolicyLog(rpc *common.RPC, fileName string) error {
	return common.Json_StrucToFile(rpc, pca.outputPath+"/RPC/"+fileName)
}