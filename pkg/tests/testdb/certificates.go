package testdb

import (
	"time"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
	"github.com/stretchr/testify/require"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/util"
)

// BuildTestCertHierarchy returns the certificates, chains, and names for two mock certificate
// chains: the first chain is domainName->c1.com->c0.com , and the second chain is
// domainName->c0.com .
func BuildTestCertHierarchy(t require.TestingT, domainName string) (
	certs []*ctx509.Certificate, IDs, parentIDs []*common.SHA256Output, names [][]string) {

	// Create all certificates.
	certs = make([]*ctx509.Certificate, 4)
	certs[0] = RandomX509Cert(t, "c0.com")
	certs[1] = RandomX509Cert(t, "c1.com")
	certs[2] = RandomX509Cert(t, domainName)
	certs[3] = RandomX509Cert(t, domainName)

	// IDs:
	IDs = make([]*common.SHA256Output, len(certs))
	for i, c := range certs {
		id := common.SHA256Hash32Bytes(c.Raw)
		IDs[i] = &id
	}

	// Names: only c2 and c3 are leaves, the rest should be nil.
	names = make([][]string, len(certs))
	names[2] = certs[2].DNSNames
	names[3] = certs[3].DNSNames

	// Parent IDs.
	parentIDs = make([]*common.SHA256Output, len(certs))
	// First chain:
	parentIDs[1] = IDs[0]
	parentIDs[2] = IDs[1]
	// Second chain:
	parentIDs[3] = IDs[0]

	return
}

func RandomX509Cert(t require.TestingT, domain string) *ctx509.Certificate {
	return &ctx509.Certificate{
		DNSNames: []string{domain},
		Subject: pkix.Name{
			CommonName: domain,
		},
		NotBefore: util.TimeFromSecs(0),
		NotAfter:  time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC),
		Raw:       util.RandomBytesForTest(t, 10),
	}
}
