package PCA

import (
	common "common.FPKI.github.com"
	"crypto/rsa"
	"errors"
	"fmt"
	"time"
)

type PCA struct {
	CAName     string
	RSAKeyPair *rsa.PrivateKey

	// store valid RPC in memory; Later replaced by data base
	ValidRPCsByDomains    map[string]*common.RPC
	PresignedRPCByDomains map[string]*common.RPC

	// newly added RPC
	NewRPCByDomains map[string]*common.RPC

	// suspicious SPTs
	SuspeciousSPTs []*common.SPT
}

func (pca *PCA) InitPCA(name, keyPath string) error {
	pca.CAName = name
	pca.ValidRPCsByDomains = make(map[string]*common.RPC)
	pca.PresignedRPCByDomains = make(map[string]*common.RPC)
	pca.NewRPCByDomains = make(map[string]*common.RPC)
	pca.SuspeciousSPTs = []*common.SPT{}

	keyPair, err := common.LoadRSAKeyPairFromFile(keyPath)
	if err != nil {
		return err
	}

	pca.RSAKeyPair = keyPair
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

	// generate pre-RPC (without SPT)
	rpc, err := common.RCSRToRPC(rcsr, notBefore, pca.GetNewSerialNumber(), pca.RSAKeyPair, pca.CAName)
	if err != nil {
		return fmt.Errorf("LogRCSR | RCSRToRPC | %s", err.Error())
	}

	pca.PresignedRPCByDomains[rpc.Subject] = rpc

	// send RPC to policy log; not implemented yet
	pca.SendRPCToPolicyLog()

	return nil
}

func (pca *PCA) SendRPCToPolicyLog() {

}

// When policy log returns SPT, this func will be called
func (pca *PCA) ReceiveSPTFromPolicyLog(spts []*common.SPT) {
	for _, spt := range spts {
		if rpc, found := pca.PresignedRPCByDomains[spt.Subject]; found {
			if pca.ValidateSPT(rpc, spt) {
				rpc.SPTs = []common.SPT{*spt}
				pca.ValidRPCsByDomains[spt.Subject] = rpc
				pca.NewRPCByDomains[spt.Subject] = rpc
				delete(pca.PresignedRPCByDomains, spt.Subject)
			}
		} else {
			pca.RecordSuspectSPT(spt)
			continue
		}
	}

}

// return the new RPC with SPT
func (pca *PCA) GetNewlyLoggedRPC(domainName string) (*common.RPC, error) {
	if rpc, found := pca.NewRPCByDomains[domainName]; found {
		delete(pca.NewRPCByDomains, domainName)
		return rpc, nil
	} else {
		return nil, errors.New("no newly logged RPC")
	}
}

// validate the SPT; To be modified after the policy log is implemented
// Logic: verify the SPT using STH and PoI
func (pca *PCA) ValidateSPT(rpc *common.RPC, spt *common.SPT) bool {
	return true
}

func (pca *PCA) RecordSuspectSPT(spt *common.SPT) {
	pca.SuspeciousSPTs = append(pca.SuspeciousSPTs, spt)
}

// TODO: modify this to make sure unique SN
func (pca *PCA) GetNewSerialNumber() int {
	return 1
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
