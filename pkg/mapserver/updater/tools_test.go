package updater

import (
	"crypto/rand"
	"testing"

	"github.com/netsec-ethz/fpki/pkg/common"
	mapCommon "github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractCertDomains(t *testing.T) {

	cert, err := common.CTX509CertFromFile("./testdata/certs/*.adiq.com.br144.cer")
	require.NoError(t, err, "projectCommon.CTX509CertFromFile")

	result := extractCertDomains(cert)
	assert.Equal(t, 2, len(result))
	assert.Contains(t, result, "*.adiq.com.br")
	assert.Contains(t, result, "adiq.com.br")
}

// TestSortDomainEntry: test SortDomainEntry()
func TestSortDomainEntry(t *testing.T) {
	// prepare test data
	cert1 := generateRandomBytes(100)
	cert2 := generateRandomBytes(100)
	cert3 := generateRandomBytes(103)
	cert4 := generateRandomBytes(10)

	caEntry1 := mapCommon.CAEntry{
		CAName:      "ca1",
		CAHash:      common.SHA256Hash([]byte("ca1")),
		DomainCerts: [][]byte{cert1, cert2, cert3, cert4},
	}

	caEntry1_ := mapCommon.CAEntry{
		CAName:      "ca1",
		CAHash:      common.SHA256Hash([]byte("ca1")),
		DomainCerts: [][]byte{cert2, cert4, cert3, cert1},
	}

	caEntry2 := mapCommon.CAEntry{
		CAName:      "ca2",
		CAHash:      common.SHA256Hash([]byte("ca2")),
		DomainCerts: [][]byte{cert1, cert2, cert3, cert4},
	}

	caEntry2_ := mapCommon.CAEntry{
		CAName:      "ca2",
		CAHash:      common.SHA256Hash([]byte("ca2")),
		DomainCerts: [][]byte{cert2, cert4, cert1, cert3},
	}

	caEntry3 := mapCommon.CAEntry{
		CAName:      "ca3",
		CAHash:      common.SHA256Hash([]byte("ca3")),
		DomainCerts: [][]byte{cert1, cert3, cert2, cert4},
	}

	caEntry3_ := mapCommon.CAEntry{
		CAName:      "ca3",
		CAHash:      common.SHA256Hash([]byte("ca3")),
		DomainCerts: [][]byte{cert2, cert1, cert3, cert4},
	}

	// add the same cert and CA entries in different orders
	domainEntry1 := &mapCommon.DomainEntry{
		CAEntry: []mapCommon.CAEntry{caEntry1, caEntry2, caEntry3_},
	}

	domainEntry2 := &mapCommon.DomainEntry{
		CAEntry: []mapCommon.CAEntry{caEntry1_, caEntry3, caEntry2_},
	}

	domainEntry3 := &mapCommon.DomainEntry{
		CAEntry: []mapCommon.CAEntry{caEntry3, caEntry2_, caEntry1_},
	}

	sortDomainEntry(domainEntry1)
	sortDomainEntry(domainEntry2)
	sortDomainEntry(domainEntry3)

	for i := 0; i < 3; i++ {
		// check ca entry order is correct
		assert.Equal(t, domainEntry1.CAEntry[i].CAName, domainEntry2.CAEntry[i].CAName, domainEntry3.CAEntry[i].CAName)
		for j := 0; j < 4; j++ {
			assert.Equal(t, domainEntry1.CAEntry[i].DomainCerts[j], domainEntry2.CAEntry[i].DomainCerts[j],
				domainEntry3.CAEntry[i].DomainCerts[j])
		}
	}
}

//-------------------------------------------------------------
//                    funcs for testing
//-------------------------------------------------------------
func generateRandomBytes(size int) []byte {
	token := make([]byte, size)
	rand.Read(token)
	return token
}
