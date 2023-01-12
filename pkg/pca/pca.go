package pca

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"log"

	"github.com/google/trillian"
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
	preRPCByDomains map[int]*common.RPC

	// RPC without SPT; pre-certificate
	preSPByDomains map[int]*common.SP

	outputPath string

	policyLogExgPath string

	// policy log's output path; receives SPT
	policyLogOutputPath string

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
		validRPCsByDomains:  make(map[string]*common.RPC),
		validSPsByDomains:   make(map[string]*common.SP),
		preRPCByDomains:     make(map[int]*common.RPC),
		preSPByDomains:      make(map[int]*common.SP),
		logVerifier:         logverifier.NewLogVerifier(nil),
		caName:              config.CAName,
		outputPath:          config.OutputPath,
		policyLogExgPath:    config.PolicyLogExgPath,
		policyLogOutputPath: config.PolicyLogOutputPath,
		rsaKeyPair:          keyPair,
	}, nil
}

// ReceiveSPTFromPolicyLog: When policy log returns SPT, this func will be called
// this func will read the SPTs from the file, and process them
func (pca *PCA) ReceiveSPTFromPolicyLog() error {
	for k, v := range pca.preRPCByDomains {
		rpcBytes, err := common.JsonStrucToBytes(v)
		if err != nil {
			return fmt.Errorf("ReceiveSPTFromPolicyLog | JsonStrucToBytes | %w", err)
		}

		// hash the rpc
		rpcHash := pca.logVerifier.HashLeaf([]byte(rpcBytes))

		// base64 url encode the hashed value, and this will be the file name of SPT
		fileName := base64.URLEncoding.EncodeToString(rpcHash)

		// read the corresponding spt
		spt := &common.SPT{}
		err = common.JsonFileToSPT(spt, pca.policyLogOutputPath+"/spt/"+fileName)
		if err != nil {
			return fmt.Errorf("ReceiveSPTFromPolicyLog | JsonFileToSPT | %w", err)
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
			// TODO(yongzhe): change this to soft-fail, or add it the suspicious SPT; for testing, we use hard-fail here
			return fmt.Errorf("Fail to verify one SPT")
		}
	}
	return nil
}

// GetValidRPCByDomain: return the new RPC with SPT
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
		poiStruc, err := common.JsonBytesToPoI(poi)
		if err != nil {
			return fmt.Errorf("verifySPT | Json_BytesToPoI | %w", err)
		}
		proofs = append(proofs, poiStruc)
	}

	// get leaf hash
	rpcBytes, err := common.JsonStrucToBytes(rpc)
	if err != nil {
		return fmt.Errorf("verifySPT | Json_StrucToBytes | %w", err)
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

// TODO(yongzhe): modify this to make sure unique SN
func (pca *PCA) increaseSerialNumber() {
	pca.serialNumber = pca.serialNumber + 1
}

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
