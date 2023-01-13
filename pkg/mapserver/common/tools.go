package common

import (
	"bytes"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/common"
)

// AddCert: add a x509 cert to one domain entry. Return whether the domain entry is updated.
func (domainEntry *DomainEntry) AddCert(cert *x509.Certificate) bool {
	caName := cert.Issuer.CommonName
	isFound := false

	// iterate CAEntry list, find if the target CA list exists
	for i := range domainEntry.CAEntry {
		if domainEntry.CAEntry[i].CAName == caName {
			isFound = true
			// check whether this certificate is already registered
			for _, certRaw := range domainEntry.CAEntry[i].DomainCerts {
				if bytes.Equal(certRaw, cert.Raw) {
					// cert already exists
					return false
				}
			}
			// if not, append the raw of the certificate
			domainEntry.CAEntry[i].DomainCerts = append(domainEntry.CAEntry[i].DomainCerts, cert.Raw)
			return true
		}
	}

	// if CA list is not found
	if !isFound {
		// add a new CA list
		domainEntry.CAEntry = append(domainEntry.CAEntry, CAEntry{
			DomainCerts: [][]byte{cert.Raw},
			CAName:      caName,
			CAHash:      common.SHA256Hash([]byte(caName))})
		return true
	}

	return false
}

// AddPC: add a Policy Certificate to a domain entry. Return whether the domain entry is updated.
func (domainEntry *DomainEntry) AddPC(pc *common.SP) bool {
	caName := pc.CAName
	isFound := false

	// iterate CAEntry list, find if the target CA list exists
	for i := range domainEntry.CAEntry {
		if domainEntry.CAEntry[i].CAName == caName {
			isFound = true
			// check whether this certificate is already registered
			if !domainEntry.CAEntry[i].CurrentPC.Equal(*pc) {
				domainEntry.CAEntry[i].CurrentPC = *pc
				return true
			}
			return false
		}
	}

	// if CA list is not found
	if !isFound {
		// add a new CA list
		domainEntry.CAEntry = append(domainEntry.CAEntry, CAEntry{
			CAName:    caName,
			CAHash:    common.SHA256Hash([]byte(caName)),
			CurrentPC: *pc,
		})
		return true
	}
	return false
}

// AddRPC: add a Root Policy Certificate to a domain entry. Return whether the domain entry is updated.
func (domainEntry *DomainEntry) AddRPC(rpc *common.RPC) bool {
	caName := rpc.CAName
	isFound := false

	// iterate CAEntry list, find if the target CA list exists
	for i := range domainEntry.CAEntry {
		if domainEntry.CAEntry[i].CAName == caName {
			isFound = true
			// check whether this certificate is already registered
			if !domainEntry.CAEntry[i].CurrentRPC.Equal(rpc) {

				domainEntry.CAEntry[i].CurrentRPC = *rpc
				return true
			}
			return false
		}
	}

	// if CA list is not found
	if !isFound {
		// add a new CA list
		domainEntry.CAEntry = append(domainEntry.CAEntry, CAEntry{
			CAName:     caName,
			CAHash:     common.SHA256Hash([]byte(caName)),
			CurrentRPC: *rpc,
		})
		return true
	}
	return false
}
