package random

import (
	"math/rand"
	"time"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/netsec-ethz/fpki/pkg/util"
	"github.com/stretchr/testify/require"
)

func RandomBytesForTest(t tests.T, size int) []byte {
	buff := make([]byte, size)
	n, err := rand.Read(buff)
	require.NoError(t, err)
	require.Equal(t, size, n)
	return buff
}

func RandomX509Cert(t tests.T, domain string) *ctx509.Certificate {
	return &ctx509.Certificate{
		DNSNames: []string{domain},
		Subject: pkix.Name{
			CommonName: domain,
		},
		NotBefore: util.TimeFromSecs(0),
		NotAfter:  time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC),
		Raw:       RandomBytesForTest(t, 10),
	}
}

// BuildTestRandomPolicyHierarchy creates two policy certificates for the given name.
func BuildTestRandomPolicyHierarchy(t tests.T, domainName string) []common.PolicyDocument {
	// Create two policy certificates for that name.
	docs := make([]common.PolicyDocument, 2)
	for i := range docs {
		pc := RandomPolicyCertificate(t)
		pc.RawSubject = domainName
		pc.Issuer = "c0.com"

		data, err := common.ToJSON(pc)
		require.NoError(t, err)
		pc.RawJSON = data
		docs[i] = pc
	}
	return docs
}

// BuildTestRandomCertHierarchy returns the certificates, chains, and names for two mock certificate
// chains: the first chain is domainName->c1.com->c0.com , and the second chain is
// domainName->c0.com .
func BuildTestRandomCertHierarchy(t tests.T, domainName string) (
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

func RandomTimeWithoutMonotonic() time.Time {
	return time.Date(
		1900+rand.Intn(200),         // 1900-2100
		time.Month(1+rand.Intn(12)), // 1-12
		1+rand.Intn(31),             // 1-31
		rand.Intn(24),               // 0-23
		rand.Intn(60),               // 0-59
		rand.Intn(60),               // 0-59
		0,
		time.UTC,
	)
}

func RandomSignedPolicyCertificateTimestamp(t tests.T) *common.SignedPolicyCertificateTimestamp {
	return common.NewSignedPolicyCertificateTimestamp(
		rand.Intn(10),                // version
		"Issuer",                     // issuer
		RandomBytesForTest(t, 10),    // log id
		RandomTimeWithoutMonotonic(), // timestamp
		RandomBytesForTest(t, 32),    // signature
	)
}

func RandomPolCertSignRequest(t tests.T) *common.PolicyCertificateSigningRequest {
	return common.NewPolicyCertificateSigningRequest(
		rand.Intn(10),
		"Issuer",
		"RPC subject",
		rand.Intn(1000), // serial number
		RandomTimeWithoutMonotonic(),
		RandomTimeWithoutMonotonic(),
		true,
		RandomBytesForTest(t, 32),
		common.RSA,
		common.SHA256,
		RandomTimeWithoutMonotonic(),
		common.PolicyAttributes{}, // policy attributes (empty for now)
		RandomBytesForTest(t, 32), // ownwer signature
		RandomBytesForTest(t, 32), // ownwer pub key hash
	)
}

func RandomPolicyCertificate(t tests.T) *common.PolicyCertificate {
	return common.NewPolicyCertificate(
		rand.Intn(10),
		"Issuer",
		"RPC subject",
		rand.Intn(1000), // serial number
		RandomTimeWithoutMonotonic(),
		RandomTimeWithoutMonotonic(),
		true,
		RandomBytesForTest(t, 32),
		common.RSA,
		common.SHA256,
		RandomTimeWithoutMonotonic(),
		common.PolicyAttributes{}, // policy attributes (empty for now)
		RandomBytesForTest(t, 32), // ownwer signature
		RandomBytesForTest(t, 32), // ownwer pub key hash
		RandomBytesForTest(t, 32), // issuer signature
		RandomBytesForTest(t, 32), // issuer pub key hash
		[]common.SignedPolicyCertificateTimestamp{
			*RandomSignedPolicyCertificateTimestamp(t),
			*RandomSignedPolicyCertificateTimestamp(t),
		},
	)
}
