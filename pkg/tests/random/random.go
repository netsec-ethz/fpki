package random

import (
	"crypto/rsa"
	"fmt"
	"io"
	"math/big"
	"math/rand"
	"time"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/netsec-ethz/fpki/pkg/util"
	"github.com/stretchr/testify/require"
)

var keyCreatingRandomCerts = RandomRSAPrivateKey(tests.NewTestObject("test_RSA_key"))

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

// RandomInt returns a random integer in the interval [from,to], both included.
func RandomInt(t tests.T, from, to int) int {
	return rand.Intn(to-from+1) + from
}

func RandomBytesForTest(t tests.T, size int) []byte {
	buff := make([]byte, size)
	n, err := rand.Read(buff)
	require.NoError(t, err)
	require.Equal(t, size, n)
	return buff
}

func RandomIDsForTest(t tests.T, size int) []common.SHA256Output {
	IDs := make([]common.SHA256Output, size)
	for i := 0; i < size; i++ {
		// Random, valid IDs.
		copy(IDs[i][:], RandomBytesForTest(t, common.SHA256Size))
	}
	return IDs
}

func RandomIDPtrsForTest(t tests.T, size int) []*common.SHA256Output {
	ids := RandomIDsForTest(t, size)
	idPtrs := make([]*common.SHA256Output, size)
	for i := range ids {
		idPtrs[i] = &ids[i]
	}
	return idPtrs
}

func RandomLeafNames(t tests.T, N int) []string {
	padding := util.Log2(uint(N))
	// Dynamic format string: as many padding zeroes as indicated by padding, e.g. leaf-%03d .
	format := fmt.Sprintf("leaf-%%0%dd", padding)

	names := make([]string, N)
	for i := 0; i < N; i++ {
		// Dynamic format string: as many padding zeroes as indicated by the variable `p` :
		names[i] = fmt.Sprintf(format, i)
	}
	return names
}

// RandomX509Cert creates a random x509 certificate, with correct ASN.1 DER representation.
func RandomX509Cert(t tests.T, domain string) ctx509.Certificate {
	template := ctx509.Certificate{
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
		&template,
		&template,
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
	// returns:
	certs []ctx509.Certificate,
	IDs []common.SHA256Output,
	parentIDs []*common.SHA256Output,
	names [][]string,
) {

	// Create all certificates.
	certs = make([]ctx509.Certificate, 4)
	certs[0] = RandomX509Cert(t, "c0.com")
	certs[1] = RandomX509Cert(t, "c1.com")
	certs[2] = RandomX509Cert(t, domainName)
	certs[3] = RandomX509Cert(t, domainName)

	// IDs:
	IDs = make([]common.SHA256Output, len(certs))
	for i, c := range certs {
		id := common.SHA256Hash32Bytes(c.Raw)
		IDs[i] = id
	}
	names = [][]string{
		{"c0.com"},
		{"c1.com"},
		certs[2].DNSNames,
		certs[3].DNSNames,
	}

	// Parent IDs.
	parentIDs = make([]*common.SHA256Output, len(certs))
	// First chain:
	parentIDs[1] = &IDs[0]
	parentIDs[2] = &IDs[1]
	// Second chain:
	parentIDs[3] = &IDs[0]

	return
}

// BuildTestRandomCertTree returns a test certificate tree.
//
//	           c0
//	           |
//	           c1
//	    /     /      \
//	   |      |       |
//	leaf1   leaf2   leaf3 .....
//
// These are the return values:
// certs[0] = c0
// certs[1] = c1
// certs[2] = leaves[0]
// certs[3] = c0
// certs[4] = c1
// certs[5] = leaves[1]
// etc.
// certs[0] == certs[3] and so on.
func BuildTestRandomCertTree(t tests.T, domainNames ...string) (
	// returns:
	certs []ctx509.Certificate,
	IDs []common.SHA256Output,
	parentIDs []*common.SHA256Output,
	names [][]string,
) {
	// Reserve return values: 3 entries per domain name.
	N := len(domainNames) * 3
	certs = make([]ctx509.Certificate, N)
	IDs = make([]common.SHA256Output, N)
	parentIDs = make([]*common.SHA256Output, N)
	names = make([][]string, N)

	// Create the ancestry.
	name0 := "c0.com"
	name1 := "c1.com"
	c0 := RandomX509Cert(t, name0)
	c1 := RandomX509Cert(t, name1)
	id0 := common.SHA256Hash32Bytes(c0.Raw)
	id1 := common.SHA256Hash32Bytes(c1.Raw)

	// For each leaf:
	for i, leaf := range domainNames {
		c0 := c0
		c1 := c1
		c := RandomX509Cert(t, leaf)
		certs[i*3+0] = c0
		certs[i*3+1] = c1
		certs[i*3+2] = c

		id0 := id0
		id1 := id1
		id := common.SHA256Hash32Bytes(c.Raw)
		IDs[i*3+0] = id0
		IDs[i*3+1] = id1
		IDs[i*3+2] = id

		parentIDs[i*3+0] = nil
		parentIDs[i*3+1] = &id0
		parentIDs[i*3+2] = &id1

		names[i*3+0] = c0.DNSNames
		names[i*3+1] = c1.DNSNames
		names[i*3+2] = c.DNSNames
	}

	return
}

// BuildTestRandomUniqueCertsTree returns a set of unique certificates.
// This function is similar to BuildTestRandomCertTree but it never returns the same ID twice.
//
//	           c0
//	           |
//	           c1
//	    /     /      \
//	   |      |       |
//	leaf1   leaf2   leaf3 .....
//
// These are the return values:
// certs[0] = c0
// certs[1] = c1
// certs[2] = leaves[0]
// certs[3] = leaves[2]
// certs[4] = leaves[3]
// etc.
func BuildTestRandomUniqueCertsTree(t tests.T, domainNames ...string) (
	// returns:
	certs []ctx509.Certificate,
	IDs []common.SHA256Output,
	parentIDs []*common.SHA256Output,
	names [][]string,
) {
	// Reserve return values: 2 entries for parents, plus leaves.
	N := len(domainNames) + 2
	certs = make([]ctx509.Certificate, N)
	IDs = make([]common.SHA256Output, N)
	parentIDs = make([]*common.SHA256Output, N)
	names = make([][]string, N)

	// Create the ancestry.
	name0 := "c0.com"
	name1 := "c1.com"
	c0 := RandomX509Cert(t, name0)
	c1 := RandomX509Cert(t, name1)
	id0 := common.SHA256Hash32Bytes(c0.Raw)
	id1 := common.SHA256Hash32Bytes(c1.Raw)
	// Store the ancestry.
	names[0] = c0.DNSNames
	names[1] = c1.DNSNames
	certs[0] = c0
	certs[1] = c1
	IDs[0] = id0
	IDs[1] = id1
	parentIDs[0] = nil
	parentIDs[1] = &id0

	// For each leaf:
	for i, leaf := range domainNames {
		c := RandomX509Cert(t, leaf)
		id := common.SHA256Hash32Bytes(c.Raw)

		certs[i+2] = c
		IDs[i+2] = id
		parentIDs[i+2] = &id1
		names[i+2] = c.DNSNames
	}

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

// RandomRSAPrivateKey generates a NON-cryptographically secure RSA private key.
func RandomRSAPrivateKey(t tests.T) *rsa.PrivateKey {
	privateKeyPair, err := rsa.GenerateKey(NewRandReader(), 2048)
	require.NoError(t, err)
	return privateKeyPair
}
