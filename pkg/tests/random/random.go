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

func BuildTestRandomPolicyHierarchy(t tests.T, domainName string) []common.PolicyObject {
	// Create one RPC and one SP for that name.
	rpc := RandomRPC(t)
	rpc.RawSubject = domainName
	rpc.CAName = "c0.com"

	data, err := common.ToJSON(rpc)
	require.NoError(t, err)
	rpc.RawJSON = data

	sp := &common.SP{
		PolicyObjectBase: common.PolicyObjectBase{
			RawSubject: domainName,
		},
		CAName:            "c0.com",
		CASignature:       RandomBytesForTest(t, 100),
		RootCertSignature: RandomBytesForTest(t, 100),
	}
	data, err = common.ToJSON(sp)
	require.NoError(t, err)
	sp.RawJSON = data

	return []common.PolicyObject{rpc, sp}
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

func RandomSPT(t tests.T) *common.SPT {
	return common.NewSPT(
		"spt subject",
		rand.Intn(10),
		"Issuer",
		rand.Intn(100000), // 0-99,999
		0x21,
		RandomTimeWithoutMonotonic(),
		RandomBytesForTest(t, 32),
		RandomBytesForTest(t, 32),
		rand.Intn(1000),
		RandomBytesForTest(t, 32),
	)
}

func RandomRPC(t tests.T) *common.RPC {
	return common.NewRPC(
		"RPC subject",
		rand.Intn(10),
		rand.Intn(10),
		common.RSA,
		RandomBytesForTest(t, 32),
		RandomTimeWithoutMonotonic(),
		RandomTimeWithoutMonotonic(),
		"Issuer",
		common.SHA256,
		RandomTimeWithoutMonotonic(),
		RandomBytesForTest(t, 32),
		RandomBytesForTest(t, 32),
		[]common.SPT{*RandomSPT(t), *RandomSPT(t)},
	)
}

func RandomSPRT(t tests.T) *common.SPRT {
	return common.NewSPRT(RandomSPT(t), rand.Intn(1000))
}

func RandomSP(t tests.T) *common.SP {
	return common.NewSP(
		"domainname.com",
		common.Policy{
			TrustedCA: []string{"ca1", "ca2"},
		},
		RandomTimeWithoutMonotonic(),
		"ca1",
		rand.Int(),
		RandomBytesForTest(t, 32),
		RandomBytesForTest(t, 32),
		[]common.SPT{
			*RandomSPT(t),
			*RandomSPT(t),
			*RandomSPT(t),
		},
	)
}

func RandomPSR(t tests.T) *common.PSR {
	return common.NewPSR(
		"domain_name.com",
		common.Policy{
			TrustedCA:         []string{"one CA", "another CA"},
			AllowedSubdomains: []string{"sub1.com", "sub2.com"},
		},
		RandomTimeWithoutMonotonic(),
		RandomBytesForTest(t, 32),
	)
}

func RandomRCSR(t tests.T) *common.RCSR {
	return common.NewRCSR(
		"subject",
		6789,
		RandomTimeWithoutMonotonic(),
		common.RSA,
		RandomBytesForTest(t, 32),
		common.SHA256,
		RandomBytesForTest(t, 32),
		RandomBytesForTest(t, 32),
	)
}
