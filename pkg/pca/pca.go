package pca

import (
	"crypto/rsa"
	"fmt"
	"log"
	"os"

	"github.com/google/trillian"
	"github.com/google/trillian/types"
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/logverifier"
	"github.com/netsec-ethz/fpki/pkg/util"
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

	// store valid Pol Cert (with server timestamps) in memory; Later replaced by data base
	validPolCertsPerDomain map[string]*common.PolicyCertificate

	// Pol Cert without timestamps; pre-certificate
	prePolCertsPerDomain map[string]*common.PolicyCertificate

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
	keyPair, err := util.RSAKeyFromPEMFile(config.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("NewPCA | LoadRSAKeyPairFromFile | %w", err)
	}
	return &PCA{
		validPolCertsPerDomain: make(map[string]*common.PolicyCertificate),
		prePolCertsPerDomain:   make(map[string]*common.PolicyCertificate),
		logVerifier:            logverifier.NewLogVerifier(nil),
		caName:                 config.CAName,
		outputPath:             config.OutputPath,
		policyLogExgPath:       config.PolicyLogExgPath,
		rsaKeyPair:             keyPair,
	}, nil
}

// ReceiveSPTFromPolicyLog: When policy log returns SPT, this func will be called
// this func will read the SPTs from the file, and process them
func (pca *PCA) ReceiveSPTFromPolicyLog() error {
	for domainName, v := range pca.prePolCertsPerDomain {
		// read the corresponding spt
		spt, err := common.JsonFileToSPT(pca.policyLogExgPath + "/spt/" + domainName)
		if err != nil {
			return fmt.Errorf("ReceiveSPTFromPolicyLog | JsonFileToSPT | %w", err)
		}

		// verify the PoI, STH
		err = pca.verifySPTWithRPC(spt, v)
		if err == nil {
			log.Printf("Get a new SPT for domain RPC: %s\n", domainName)
			v.SPTs = []common.SignedPolicyCertificateTimestamp{*spt}

			// move the rpc from pre-rpc to valid-rpc
			delete(pca.prePolCertsPerDomain, domainName)
			pca.validPolCertsPerDomain[v.RawSubject] = v
		} else {
			return fmt.Errorf("Fail to verify one SPT RPC")
		}
		os.Remove(pca.policyLogExgPath + "/spt/" + domainName)
	}

	return nil
}

func (pca *PCA) OutputPolicyCertificate() error {
	for domain, rpc := range pca.validPolCertsPerDomain {
		err := common.ToJSONFile(rpc, pca.outputPath+"/"+domain+"_"+rpc.Issuer+"_"+"rpc")
		if err != nil {
			return fmt.Errorf("OutputPolicyCertificate | JsonStructToFile | %w", err)
		}
	}
	return nil
}

// verify the SPT of the RPC.
func (pca *PCA) verifySPTWithRPC(spt *common.SignedPolicyCertificateTimestamp, rpc *common.PolicyCertificate) error {
	proofs, logRoot, err := getProofsAndLogRoot(spt)
	if err != nil {
		return fmt.Errorf("verifySPTWithRPC | parsePoIAndSTH | %w", err)
	}

	// get leaf hash
	rpcBytes, err := common.ToJSON(rpc)
	if err != nil {
		return fmt.Errorf("verifySPT | Json_StructToBytes | %w", err)
	}
	leafHash := pca.logVerifier.HashLeaf(rpcBytes)

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

func (pca *PCA) ReturnValidRPC() map[string]*common.PolicyCertificate {
	return pca.validPolCertsPerDomain
}

// getProofsAndLogRoot return the proofs and root parsed from the PoI and STH in JSON.
func getProofsAndLogRoot(spt *common.SignedPolicyCertificateTimestamp) ([]*trillian.Proof, *types.LogRootV1, error) {
	// Parse the PoI into []*trillian.Proof.
	serializedProofs, err := common.FromJSON(spt.PoI)
	if err != nil {
		return nil, nil, err
	}
	proofs, err := util.ToTypedSlice[*trillian.Proof](serializedProofs)
	if err != nil {
		return nil, nil, err
	}

	// Parse the STH into a *types.LogRootV1.
	serializedRoot, err := common.FromJSON(spt.STH)
	if err != nil {
		return nil, nil, err
	}
	root, err := util.ToType[*types.LogRootV1](serializedRoot)
	if err != nil {
		return nil, nil, err
	}

	return proofs, root, nil
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
