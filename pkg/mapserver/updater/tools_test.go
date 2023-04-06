package updater

import (
	"crypto/rand"
	"testing"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExtractCertDomains: test extractCertDomains()
func TestExtractCertDomains(t *testing.T) {

	cert, err := common.CTX509CertFromFile("./testdata/certs/adiq.com.br144.cer")
	require.NoError(t, err, "projectCommon.CTX509CertFromFile")

	result := util.ExtractCertDomains(cert)
	assert.Equal(t, 2, len(result))
	assert.Contains(t, result, "*.adiq.com.br")
	assert.Contains(t, result, "adiq.com.br")
}

// TestSortDomainEntry: test SortDomainEntry()
func TestSortDomainEntry(t *testing.T) {
	// // prepare test data
	// cert1 := generateRandomBytes(100)
	// cert2 := generateRandomBytes(100)
	// cert3 := generateRandomBytes(103)
	// cert4 := generateRandomBytes(10)

	// caEntry1 := mapCommon.Entry{
	// 	CAName:      "ca1",
	// 	CAHash:      common.SHA256Hash([]byte("ca1")),
	// 	DomainCerts: [][]byte{cert1, cert2, cert3, cert4},
	// }

	// caEntry1_ := mapCommon.Entry{
	// 	CAName:      "ca1",
	// 	CAHash:      common.SHA256Hash([]byte("ca1")),
	// 	DomainCerts: [][]byte{cert2, cert4, cert3, cert1},
	// }

	// caEntry2 := mapCommon.Entry{
	// 	CAName:      "ca2",
	// 	CAHash:      common.SHA256Hash([]byte("ca2")),
	// 	DomainCerts: [][]byte{cert1, cert2, cert3, cert4},
	// }

	// caEntry2_ := mapCommon.Entry{
	// 	CAName:      "ca2",
	// 	CAHash:      common.SHA256Hash([]byte("ca2")),
	// 	DomainCerts: [][]byte{cert2, cert4, cert1, cert3},
	// }

	// caEntry3 := mapCommon.Entry{
	// 	CAName:      "ca3",
	// 	CAHash:      common.SHA256Hash([]byte("ca3")),
	// 	DomainCerts: [][]byte{cert1, cert3, cert2, cert4},
	// }

	// caEntry3_ := mapCommon.Entry{
	// 	CAName:      "ca3",
	// 	CAHash:      common.SHA256Hash([]byte("ca3")),
	// 	DomainCerts: [][]byte{cert2, cert1, cert3, cert4},
	// }

	// // add the same cert and CA entries in different orders
	// domainEntry1 := &mapCommon.DomainEntry{
	// 	Entries: []mapCommon.Entry{caEntry1, caEntry2, caEntry3_},
	// }

	// domainEntry2 := &mapCommon.DomainEntry{
	// 	Entries: []mapCommon.Entry{caEntry1_, caEntry3, caEntry2_},
	// }

	// domainEntry3 := &mapCommon.DomainEntry{
	// 	Entries: []mapCommon.Entry{caEntry3, caEntry2_, caEntry1_},
	// }

	// sortDomainEntry(domainEntry1)
	// sortDomainEntry(domainEntry2)
	// sortDomainEntry(domainEntry3)

	// for i := 0; i < 3; i++ {
	// 	// check ca entry order is correct
	// 	assert.Equal(t, domainEntry1.Entries[i].CAName, domainEntry2.Entries[i].CAName, domainEntry3.Entries[i].CAName)
	// 	for j := 0; j < 4; j++ {
	// 		assert.Equal(t, domainEntry1.Entries[i].DomainCerts[j], domainEntry2.Entries[i].DomainCerts[j],
	// 			domainEntry3.Entries[i].DomainCerts[j])
	// 	}
	// }
}

// -------------------------------------------------------------
//
//	funcs for testing
//
// -------------------------------------------------------------
func generateRandomBytes(size int) []byte {
	token := make([]byte, size)
	rand.Read(token)
	return token
}
