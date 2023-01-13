package pca

import (
	"crypto/rsa"
	"fmt"
	"log"
	"os"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/logverifier"
)

// CRITICAL: The funcs are not thread-safe for now. DO NOT use them for multi-thread program.

// TODO(yongzhe):
//       How to handle Cool-off period?
//       SuspiciousSPTs
//       Let domain owner sends the previous RPC (PCA needs to store the RPC anyway, right?
//           If domain owner loses the RPC, PCA can return the missing RPC)
//       More complete logic

// PCA: Structure which represent one PCA
type PCA struct {
	caName string

	// pca's signing rsa key pair; used to sign rcsr -> rpc
	rsaKeyPair *rsa.PrivateKey

	// store valid RPC (with SPT) in memory; Later replaced by data base
	validRPCsByDomains map[string]*common.RPC

	validSPsByDomains map[string]*common.SP

	// RPC without SPT; pre-certificate
	preRPCByDomains map[string]*common.RPC

	// RPC without SPT; pre-certificate
	preSPByDomains map[string]*common.SP

	policyLogExgPath string

	outputPath string

	// verifier to verify the STH and PoI
	logVerifier *logverifier.LogVerifier

	// serial number for the RPC; unique for every RPC
	serialNumber int
}

// NewPCA: Return a new instance of PCa
func NewPCA(configPath string) (*PCA, error) {
	// read config file
	config := &PCAConfig{}
	err := ReadConfigFromFile(config, configPath)
	if err != nil {
		return nil, fmt.Errorf("NewPCA | ReadConfigFromFile | %w", err)
	}
	// load rsa key pair
	keyPair, err := common.LoadRSAKeyPairFromFile(config.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("NewPCA | LoadRSAKeyPairFromFile | %w", err)
	}
	return &PCA{
		validRPCsByDomains: make(map[string]*common.RPC),
		validSPsByDomains:  make(map[string]*common.SP),
		preRPCByDomains:    make(map[string]*common.RPC),
		preSPByDomains:     make(map[string]*common.SP),
		logVerifier:        logverifier.NewLogVerifier(nil),
		caName:             config.CAName,
		outputPath:         config.OutputPath,
		policyLogExgPath:   config.PolicyLogExgPath,
		rsaKeyPair:         keyPair,
	}, nil
}

// ReceiveSPTFromPolicyLog: When policy log returns SPT, this func will be called
// this func will read the SPTs from the file, and process them
func (pca *PCA) ReceiveSPTFromPolicyLog() error {
	for k, v := range pca.preRPCByDomains {
		// read the corresponding spt
		spt := &common.SPT{}
		err := common.JsonFileToSPT(spt, pca.policyLogExgPath+"/spt/"+k)
		if err != nil {
			return fmt.Errorf("ReceiveSPTFromPolicyLog | JsonFileToSPT | %w", err)
		}

		// verify the PoI, STH
		err = pca.verifySPTWithRPC(spt, v)
		if err == nil {
			log.Printf("Get a new SPT for domain RPC: %s\n", k)
			v.SPTs = []common.SPT{*spt}

			// move the rpc from pre-rpc to valid-rpc
			delete(pca.preRPCByDomains, k)
			pca.validRPCsByDomains[v.Subject] = v
		} else {
			return fmt.Errorf("Fail to verify one SPT RPC")
		}
		os.Remove(pca.policyLogExgPath + "/spt/" + k)
	}

	for k, v := range pca.preSPByDomains {
		// read the corresponding spt
		spt := &common.SPT{}
		err := common.JsonFileToSPT(spt, pca.policyLogExgPath+"/spt/"+k)
		if err != nil {
			return fmt.Errorf("ReceiveSPTFromPolicyLog | JsonFileToSPT | %w", err)
		}

		// verify the PoI, STH
		err = pca.verifySPTWithSP(spt, v)
		if err == nil {
			log.Printf("Get a new SPT for domain SP: %s\n", k)
			v.SPTs = []common.SPT{*spt}

			// move the rpc from pre-rpc to valid-rpc
			delete(pca.preRPCByDomains, k)
			pca.validSPsByDomains[v.Subject] = v
		} else {
			return fmt.Errorf("Fail to verify one SPT SP")
		}
		os.Remove(pca.policyLogExgPath + "/spt/" + k)
	}

	return nil
}

func (pca *PCA) OutputRPCAndSP() error {
	for domain, rpc := range pca.validRPCsByDomains {
		err := common.JsonStructToFile(rpc, pca.outputPath+"/"+domain+"_"+rpc.CAName+"_"+"rpc")
		if err != nil {
			return fmt.Errorf("OutputRPCAndSP | JsonStructToFile | %w", err)
		}
	}

	for domain, rpc := range pca.validSPsByDomains {
		err := common.JsonStructToFile(rpc, pca.outputPath+"/"+domain+"_"+rpc.CAName+"_"+"sp")
		if err != nil {
			return fmt.Errorf("OutputRPCAndSP | JsonStructToFile | %w", err)
		}
	}
	return nil
}

// verify the SPT of the RPC.
func (pca *PCA) verifySPTWithRPC(spt *common.SPT, rpc *common.RPC) error {
	// construct proofs

	proofs, err := common.JsonBytesToPoI(spt.PoI)
	if err != nil {
		return fmt.Errorf("verifySPT | JsonBytesToPoI | %w", err)
	}

	// get leaf hash
	rpcBytes, err := common.JsonStructToBytes(rpc)
	if err != nil {
		return fmt.Errorf("verifySPT | Json_StructToBytes | %w", err)
	}
	leafHash := pca.logVerifier.HashLeaf(rpcBytes)

	// get LogRootV1
	logRoot, err := common.JsonBytesToLogRoot(spt.STH)
	if err != nil {
		return fmt.Errorf("verifySPT | JsonBytesToLogRoot | %w", err)
	}

	// verify the PoI
	err = pca.logVerifier.VerifyInclusionByHash(logRoot, leafHash, proofs)
	if err != nil {
		return fmt.Errorf("verifySPT | VerifyInclusionByHash | %w", err)
	}

	return nil
}

// verify the SPT of the RPC.
func (pca *PCA) verifySPTWithSP(spt *common.SPT, sp *common.SP) error {
	// construct proofs
	proofs, err := common.JsonBytesToPoI(spt.PoI)
	if err != nil {
		return fmt.Errorf("verifySPT | JsonBytesToPoI | %w", err)
	}

	// get leaf hash
	spBytes, err := common.JsonStructToBytes(sp)
	if err != nil {
		return fmt.Errorf("verifySPT | Json_StructToBytes | %w", err)
	}
	leafHash := pca.logVerifier.HashLeaf(spBytes)

	// get LogRootV1
	logRoot, err := common.JsonBytesToLogRoot(spt.STH)
	if err != nil {
		return fmt.Errorf("verifySPT | JsonBytesToLogRoot | %w", err)
	}

	// verify the PoI
	err = pca.logVerifier.VerifyInclusionByHash(logRoot, leafHash, proofs)
	if err != nil {
		return fmt.Errorf("verifySPT | VerifyInclusionByHash | %w", err)
	}

	return nil
}

// TODO(yongzhe): modify this to make sure unique SN
func (pca *PCA) increaseSerialNumber() {
	pca.serialNumber = pca.serialNumber + 1
}

func (pca *PCA) ReturnValidRPC() map[string]*common.RPC {
	return pca.validRPCsByDomains
}

/*
// check whether the RPC signature is correct
func (pca *PCA) checkRPCSignature(rcsr *common.RCSR) bool {
	// if no rpc signature
	if len(rcsr.PRCSignature) == 0 {
		return false
	}

	// check if there is any valid rpc
	if rpc, found := pca.validRPCsByDomains[rcsr.Subject]; found {
		err := common.RCSRVerifyRPCSignature(rcsr, rpc)
		if err == nil {
			return true
		} else {
			return false
		}
	} else {
		return false
	}
}

// GetValidRPCByDomain: return the new RPC with SPT
func (pca *PCA) GetValidRPCByDomain(domainName string) (*common.RPC, error) {
	if rpc, found := pca.validRPCsByDomains[domainName]; found {
		return rpc, nil
	} else {
		return nil, errors.New("no valid RPC")
	}
}
*/
