package updater

import (
	"encoding/hex"
	"fmt"

	ctx509 "github.com/google/certificate-transparency-go/x509"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/util"
)

// CertWithChainData represents a parsed certificate structure, either from a server or from
// a CSV file.
// This structure contains the certificate itself, plus all its parents.
type CertWithChainData struct {
	CertID        common.SHA256Output    // The ID (the SHA256) of the certificate.
	Cert          *ctx509.Certificate    // The payload of the certificate.
	ChainPayloads []*ctx509.Certificate  // The payloads of the chain. Is nil if already cached.
	ChainIDs      []*common.SHA256Output // The trust chain of the certificate.
}

func (c CertWithChainData) String() string {
	return fmt.Sprintf("chain-for-%s", hex.EncodeToString(c.CertID[:]))
}

// Certificate contains all the data of just ONE certificate, without the parents.
// It results from a call to util.UnfoldCert .
type Certificate struct {
	CertID   common.SHA256Output
	Cert     ctx509.Certificate
	ParentID *common.SHA256Output
	Names    []string
}

func (c Certificate) String() string {
	return hex.EncodeToString(c.CertID[:])
}

type DirtyDomain struct {
	DomainID common.SHA256Output
	CertID   common.SHA256Output
	Name     string
}

func (d DirtyDomain) String() string {
	return hex.EncodeToString(d.DomainID[:])
}

func CertificatesFromChains(data *CertWithChainData) []Certificate {
	payloads, certIDs, parentIDs, names := util.UnfoldCert(data.Cert, data.CertID,
		data.ChainPayloads, data.ChainIDs)

	certs := make([]Certificate, len(payloads))
	for i := range payloads {
		// Add the certificate.
		certs[i] = Certificate{
			CertID:   certIDs[i],
			Cert:     payloads[i],
			ParentID: parentIDs[i],
			Names:    names[i],
		}
	}

	return certs
}

func CertificatePtrsFromChains(data *CertWithChainData) []*Certificate {
	certs := CertificatesFromChains(data)
	certPtrs := make([]*Certificate, len(certs))
	for i, c := range certs {
		c := c
		certPtrs[i] = &c
	}

	return certPtrs
}
