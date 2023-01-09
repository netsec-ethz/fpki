package common

import (
	"bytes"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/common"
)

func findCertificateChain(cert *x509.Certificate, certChain []*x509.Certificate) (chain []*x509.Certificate) {
	chain = append(chain, cert)
	// each certificate occurs at most once in the certificate chain thus we have to find the issuer certificate at most as often as the length of the chain
	for i := 0; i < len(certChain); i++ {
		// check for self-signed certificates
		if chain[len(chain)-1].Issuer.ToRDNSequence().String() == chain[len(chain)-1].Subject.ToRDNSequence().String() {
			// we arrived at a self-signed certificate, so we can stop searching for issuer certificates
			break
		}

		// find issuer certificate
		for _, c := range certChain {
			if chain[len(chain)-1].Issuer.ToRDNSequence().String() == c.Subject.ToRDNSequence().String() {
				chain = append(chain, c)
				break
			}
		}
	}
	return chain
}

func getRootCertificateSubject(cert *x509.Certificate, certChain []*x509.Certificate) string {
	constructedCertChain := findCertificateChain(cert, certChain)
	rootCert := constructedCertChain[len(constructedCertChain)-1]
	return rootCert.Issuer.ToRDNSequence().String()
}

// AddCert: add a x509 cert to one domain entry. Return whether the domain entry is updated.
func (domainEntry *DomainEntry) AddCert(cert *x509.Certificate, certChain []*x509.Certificate) bool {
	caName := getRootCertificateSubject(cert, certChain)

	isFound := false

	// convert the certificate chain into an array of raw bytes and append them to the same CA Entry in the same order
	var rawCertChain [][]byte
	for _, certChainItem := range certChain {
		rawCertChain = append(rawCertChain, certChainItem.Raw)
	}

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
			domainEntry.CAEntry[i].DomainCertChains = append(domainEntry.CAEntry[i].DomainCertChains, rawCertChain)
			return true
		}
	}

	// if CA list is not found
	if !isFound {
		// add a new CA list
		domainEntry.CAEntry = append(domainEntry.CAEntry, CAEntry{
			DomainCerts:      [][]byte{cert.Raw},
			DomainCertChains: [][][]byte{rawCertChain},
			CAName:           caName,
			CAHash:           common.SHA256Hash([]byte(caName))})
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
