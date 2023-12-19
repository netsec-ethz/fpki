package random

import (
	"crypto/rsa"
	"io"
	"math/big"
	"math/rand"
	"time"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/stretchr/testify/require"
)

// randReader is a type implementing io.Reader which _fools_ `rsa.GenerateKey` to always generate
// reproducible keys if the random source is deterministic (reproducible).
// Use this reader only in tests.
type randReader struct{}

func (randReader) Read(p []byte) (int, error) {
	if len(p) == 1 {
		return 1, nil
	}
	return rand.Read(p)
}

// NewRandReader returns an io.Reader that forces rsa.GenerateKeys to generate reproducible keys,
// iff the random source is deterministic. Make a prior call to `rand.Seed()` to obtain
// deterministic results, otherwise the random source will be pseudorandom but
// probably not reproducible.
func NewRandReader() io.Reader {
	return randReader{}
}

func RandomBytesForTest(t tests.T, size int) []byte {
	buff := make([]byte, size)
	n, err := rand.Read(buff)
	require.NoError(t, err)
	require.Equal(t, size, n)
	return buff
}

var keyCreatingRandomCerts = RandomRSAPrivateKey(tests.NewTestObject("test_RSA_key"))

// RandomX509Cert creates a random x509 certificate, with correct ASN.1 DER representation.
func RandomX509Cert(t tests.T, domain string) *ctx509.Certificate {
	template := &ctx509.Certificate{
		SerialNumber: big.NewInt(rand.Int63()),
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames:  []string{domain},
		NotBefore: RandomTimeWithoutMonotonicBounded(1900, 2000),
		NotAfter:  RandomTimeWithoutMonotonicBounded(2200, 2300),
		KeyUsage:  ctx509.KeyUsageKeyEncipherment | ctx509.KeyUsageDigitalSignature,
	}
	derBytes, err := ctx509.CreateCertificate(
		NewRandReader(),
		template,
		template,
		&keyCreatingRandomCerts.PublicKey,
		keyCreatingRandomCerts,
	)
	require.NoError(t, err)
	template.Raw = derBytes

	return template
}

// BuildTestRandomPolicyHierarchy creates two policy certificates for the given name.
func BuildTestRandomPolicyHierarchy(t tests.T, domainName string) []common.PolicyDocument {
	// Create two policy certificates for that name.
	docs := make([]common.PolicyDocument, 2)
	for i := range docs {
		pc := RandomPolicyCertificate(t)
		pc.DomainField = domainName
		pc.IssuerHash = RandomBytesForTest(t, 32)

		data, err := common.ToJSON(pc)
		require.NoError(t, err)
		pc.JSONField = data
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

func RandomTimeWithoutMonotonicBounded(minYear, maxYear int) time.Time {
	return time.Date(
		minYear+rand.Intn(maxYear-minYear+1),
		time.Month(1+rand.Intn(12)), // 1-12
		1+rand.Intn(31),             // 1-31
		rand.Intn(24),               // 0-23
		rand.Intn(60),               // 0-59
		rand.Intn(60),               // 0-59
		0,
		time.UTC,
	)
}

func RandomTimeWithoutMonotonic() time.Time {
	return RandomTimeWithoutMonotonicBounded(1900, 2099)
}

func RandomSignedPolicyCertificateTimestamp(t tests.T) *common.SignedPolicyCertificateTimestamp {
	return common.NewSignedPolicyCertificateTimestamp(
		rand.Intn(10),                // version
		RandomBytesForTest(t, 10),    // log id
		RandomTimeWithoutMonotonic(), // timestamp
		RandomBytesForTest(t, 32),    // signature
	)
}

func RandomSignedPolicyCertificateRevocationTimestamp(
	t tests.T,
) *common.SignedPolicyCertificateRevocationTimestamp {

	return common.NewSignedPolicyCertificateRevocationTimestamp(
		rand.Intn(10),                // version
		RandomBytesForTest(t, 10),    // log id
		RandomTimeWithoutMonotonic(), // timestamp
		RandomBytesForTest(t, 32),    // signature
	)
}

func RandomPolCertSignRequest(t tests.T) *common.PolicyCertificateSigningRequest {
	return common.NewPolicyCertificateSigningRequest(
		rand.Intn(10),
		rand.Intn(1000), // serial number
		"domain",        // domain
		RandomTimeWithoutMonotonic(),
		RandomTimeWithoutMonotonic(),
		true,                      // can issue
		true,                      // can own
		RandomBytesForTest(t, 32), // public key
		common.RSA,
		common.SHA256,
		RandomTimeWithoutMonotonic(), // timestamp
		common.PolicyAttributes{},    // policy attributes (empty for now)
		RandomBytesForTest(t, 32),    // owner signature
		RandomBytesForTest(t, 32),    // owner hash
	)
}

func RandomPolicyCertificate(t tests.T) *common.PolicyCertificate {
	return common.NewPolicyCertificate(
		rand.Intn(10),
		rand.Intn(1000), // serial number
		"fpki.com",
		RandomTimeWithoutMonotonic(),
		RandomTimeWithoutMonotonic(),
		true,                      // can issue
		true,                      // can own
		RandomBytesForTest(t, 32), // public key
		common.RSA,
		common.SHA256,
		RandomTimeWithoutMonotonic(), // timestamp
		common.PolicyAttributes{},    // policy attributes (empty for now)
		RandomBytesForTest(t, 32),    // owner signature
		RandomBytesForTest(t, 32),    // owner hash
		[]common.SignedPolicyCertificateTimestamp{
			*RandomSignedPolicyCertificateTimestamp(t),
			*RandomSignedPolicyCertificateTimestamp(t),
		},
		RandomBytesForTest(t, 32), // issuer signature
		RandomBytesForTest(t, 32), // issuer hash
	)
}

func RandomPolicyCertificateRevocationSigningRequest(t tests.T) *common.PolicyCertificateRevocationSigningRequest {
	return common.NewPolicyCertificateRevocationSigningRequest(
		RandomBytesForTest(t, 32), // hash of the pol cert to revoke
	)
}

func RandomPolicyCertificateRevocation(t tests.T) *common.PolicyCertificateRevocation {
	return common.NewPolicyCertificateRevocation(
		rand.Intn(10),                // version
		rand.Intn(1000),              // serial number
		RandomTimeWithoutMonotonic(), // timestamp
		RandomBytesForTest(t, 32),    // owner signature
		RandomBytesForTest(t, 32),    // owner hash
		[]common.SignedPolicyCertificateRevocationTimestamp{
			*RandomSignedPolicyCertificateRevocationTimestamp(t),
			*RandomSignedPolicyCertificateRevocationTimestamp(t),
		},
		RandomBytesForTest(t, 32), // issuer signature
		RandomBytesForTest(t, 32), // issuer hash
	)
}

// RandomRSAPrivateKey generates a NON-cryptographycally secure RSA private key.
func RandomRSAPrivateKey(t tests.T) *rsa.PrivateKey {
	privateKeyPair, err := rsa.GenerateKey(NewRandReader(), 2048)
	require.NoError(t, err)
	return privateKeyPair
}
