package PCA

import (
	PL_LogVerifier "PL_LogVerifier.FPKI.github.com"
	common "common.FPKI.github.com"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/google/trillian"
	"io/ioutil"
	"log"
	"strconv"
	"time"
)

// TODO: How to handle Cool-off period?
//       SuspeciousSPTs
//       Let domain owner send the previous RPC (PCA needs to store the RPC anyway, right? If domain owner loses the RPC, PCA can return the missing RPC)
//       More complete logic
type PCA struct {
	CAName     string
	RSAKeyPair *rsa.PrivateKey

	// store valid RPC (with SPT) in memory; Later replaced by data base
	ValidRPCsByDomains map[string]*common.RPC

	// RPC whitout SPT
	PreRPCByDomains map[string]*common.RPC

	OutputPath string

	LogVerifier *PL_LogVerifier.LogVerifier

	serialNumber int

	policyLogOutputPath string
}

func (pca *PCA) InitPCA(name, keyPath, outputPath string, policyLogOutputPath string) error {
	pca.CAName = name
	pca.ValidRPCsByDomains = make(map[string]*common.RPC)
	pca.PreRPCByDomains = make(map[string]*common.RPC)
	//pca.SuspeciousSPTs = []*common.SPT{}

	pca.OutputPath = outputPath

	keyPair, err := common.LoadRSAKeyPairFromFile(keyPath)
	if err != nil {
		return err
	}

	pca.RSAKeyPair = keyPair

	pca.policyLogOutputPath = policyLogOutputPath

	pca.serialNumber = 0

	pca.LogVerifier = PL_LogVerifier.NewLogVerifier(nil)
	return nil
}

func (pca *PCA) SignAndLogRCSR(rcsr *common.RCSR) error {
	err := common.VerifyRCSR(rcsr)
	if err != nil {
		return err
	}

	// decide not before time
	var notBefore time.Time
	if pca.CheckRPCSignature(rcsr) {
		notBefore = time.Now()
	} else {
		// cool off period
		notBefore = time.Now().AddDate(0, 0, 7)
	}

	pca.increaseSerialNumber()

	// generate pre-RPC (without SPT)
	rpc, err := common.RCSRToRPC(rcsr, notBefore, pca.getSerialNumber(), pca.RSAKeyPair, pca.CAName)
	if err != nil {
		return fmt.Errorf("LogRCSR | RCSRToRPC | %s", err.Error())
	}

	pca.PreRPCByDomains[rpc.Subject] = rpc

	fmt.Println(pca.getSerialNumber())
	// send RPC to policy log; not implemented yet
	err = pca.SendRPCToPolicyLog(rpc, strconv.Itoa(pca.getSerialNumber()))

	if err != nil {
		return fmt.Errorf("LogRCSR | SendRPCToPolicyLog | %s", err.Error())
	}

	return nil
}

// save file to output dir
func (pca *PCA) SendRPCToPolicyLog(rpc *common.RPC, fileName string) error {
	fmt.Println(fileName)
	return common.Json_WriteStrucToFile(rpc, pca.OutputPath+"/RPC/"+fileName)
}

// When policy log returns SPT, this func will be called
func (pca *PCA) ReceiveSPTFromPolicyLog() error {
	for k, v := range pca.PreRPCByDomains {
		rpcBytes, err := common.Json_RPCBytesToBytes(v)
		rpcHash := pca.LogVerifier.HashLeaf([]byte(rpcBytes))
		fileName := base64.URLEncoding.EncodeToString(rpcHash)

		fmt.Println(fileName)

		if err != nil {
			return err
		}
		bytes, err := ioutil.ReadFile(pca.policyLogOutputPath + "/spt/" + fileName[:])
		if err != nil {
			// SPT is not ready yet or other file errors
			// TODO: add warning
			log.Printf("No valid SPT for domain: %s\n", k)
			continue
		}

		spt, err := common.Json_BytesToSPT(bytes)
		if err != nil {
			return fmt.Errorf("ReceiveSPTFromPolicyLog | DeserialiseSPT | %s", err.Error())
		}

		err = pca.verifySPT(spt, v)
		if err == nil {
			log.Printf("Get a new SPT for domain: %s\n", k)
			v.SPTs = []common.SPT{*spt}
			delete(pca.PreRPCByDomains, k)
			pca.ValidRPCsByDomains[k] = v
		} else {
			log.Printf("fail to verify")
			fmt.Println(err)
		}
	}

	return nil
}

// verify the SPT of the RPC.
func (pca *PCA) verifySPT(spt *common.SPT, rpc *common.RPC) error {
	// construct proofs
	proofs := []*trillian.Proof{}
	for _, poi := range spt.PoI {
		poiStruc, err := common.Json_BytesToPoI(poi)
		if err != nil {
			return fmt.Errorf("verifySPT | DeserialiseSPT | %s", err.Error())
		}

		proofs = append(proofs, poiStruc)
	}

	// get leaf hash
	rpcBytes, err := common.Json_RPCBytesToBytes(rpc)
	if err != nil {
		return fmt.Errorf("verifySPT | SerialiseStruc | %s", err.Error())
	}
	leafHash := pca.LogVerifier.HashLeaf(rpcBytes)

	// get LogRootV1
	logRoot, err := pca.LogVerifier.DeserialiseLogRoot(spt.STH)

	err = pca.LogVerifier.VerifyInclusionByHash(logRoot, leafHash, proofs)
	return err
}

// return the new RPC with SPT
func (pca *PCA) GetValidRPCByDomain(domainName string) (*common.RPC, error) {
	if rpc, found := pca.ValidRPCsByDomains[domainName]; found {
		return rpc, nil
	} else {
		return nil, errors.New("no valid RPC")
	}
}

/*
func (pca *PCA) RecordSuspectSPT(spt *common.SPT) {
	pca.SuspeciousSPTs = append(pca.SuspeciousSPTs, spt)
}
*/

// TODO: modify this to make sure unique SN
func (pca *PCA) getSerialNumber() int {
	return pca.serialNumber
}

// TODO: modify this to make sure unique SN
func (pca *PCA) increaseSerialNumber() {
	pca.serialNumber = pca.serialNumber + 1
}

func (pca *PCA) CheckRPCSignature(rcsr *common.RCSR) bool {
	if rpc, found := pca.ValidRPCsByDomains[rcsr.Subject]; found {
		err := common.VerifyRCSRByRPC(rcsr, rpc)
		if err == nil {
			return true
		} else {
			return false
		}
	} else {
		return false
	}
}
