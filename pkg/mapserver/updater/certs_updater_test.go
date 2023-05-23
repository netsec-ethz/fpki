package updater

import (
	"bytes"
	"io/ioutil"
	"testing"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/domain"
	mapCommon "github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/util"
)

// TestUpdateDomainEntriesUsingCerts: test UpdateDomainEntriesUsingCerts
// This test tests the individual functions of the UpdateDomainEntriesUsingCerts()
func TestUpdateDomainEntriesUsingCerts(t *testing.T) {
	t.Skip() // deleteme

	certs := []*ctx509.Certificate{}

	// load test certs
	files, err := ioutil.ReadDir("./testdata/certs/")
	require.NoError(t, err, "ioutil.ReadDir")
	certChains := make([][]*ctx509.Certificate, len(files))
	for _, file := range files {
		cert, err := common.CTX509CertFromFile("./testdata/certs/" + file.Name())
		require.NoError(t, err, "projectCommon.CTX509CertFromFile")
		certs = append(certs, cert)
	}

	// get affected domain map and domain cert map
	affectedDomainsMap, domainCertMap, domainCertChainMap := GetAffectedDomainAndCertMap(
		certs, certChains)

	// test if all the certs are correctly added to the affectedDomainsMap and domainCertMap
	for _, cert := range certs {
		// get common name and SAN of the certificate
		domainNames := util.ExtractCertDomains(cert)

		// get the valid domain name from domainNames list
		affectedDomains := domain.ExtractAffectedDomains(domainNames)
		if len(affectedDomains) == 0 {
			// if cert does not have a valid domain name
			continue
		}

		// check the affected domain is correctly added to the affectedDomains
		for _, affectedDomain := range affectedDomains {
			var affectedNameHash common.SHA256Output
			copy(affectedNameHash[:], common.SHA256Hash([]byte(affectedDomain)))

			_, ok := affectedDomainsMap[affectedNameHash]
			assert.True(t, ok, "domain not found in affectedDomainsMap")
		}

		// check if the domainCertMap is correct
		for domainName, newCerts := range domainCertMap {
			if includedIn(affectedDomains, domainName) {
				isFound := false
				for _, newCert := range newCerts {
					if bytes.Equal(newCert.Raw, cert.Raw) {
						isFound = true
					}
				}
				assert.True(t, isFound, "cert not found in domainCertMap")
			} else {
				for _, newCert := range newCerts {
					assert.False(t, bytes.Equal(newCert.Raw, cert.Raw), "cert should not be here")
				}
			}
		}
	}

	// empty domainEntriesMap
	domainEntriesMap := make(map[common.SHA256Output]*mapCommon.DomainEntry)
	updatedDomains, err := UpdateDomainEntries(domainEntriesMap, domainCertMap, domainCertChainMap)
	require.NoError(t, err, "updateDomainEntries")

	assert.Equal(t, len(updatedDomains), len(affectedDomainsMap), "len(updatedDomains) should equals to len(affectedDomainsMap)")

	// check if domainEntriesMap is correctly updated
	for _, cert := range certs {
		domainNames := util.ExtractCertDomains(cert)
		// caName := cert.Issuer.String()

		// check if this cert has valid name
		affectedDomains := domain.ExtractAffectedDomains(domainNames)
		if len(affectedDomains) == 0 {
			continue
		}

		// check domainEntriesMap
		for _, domainName := range affectedDomains {
			var domainHash common.SHA256Output
			copy(domainHash[:], common.SHA256Hash([]byte(domainName)))

			domainEntry, ok := domainEntriesMap[domainHash]
			assert.True(t, ok, "domainEntriesMap error")

			// check domain name is correct
			assert.True(t, domainEntry.DomainName == domainName)
			// for _, caList := range domainEntry.Entries {
			// 	if caList.CAName == caName {
			// 		isFound := false
			// 		for _, newCert := range caList.DomainCerts {
			// 			if bytes.Equal(newCert, cert.Raw) {
			// 				isFound = true
			// 			}
			// 		}
			// 		assert.True(t, isFound, "cert not found")
			// 	} else {
			// 		for _, newCert := range caList.DomainCerts {
			// 			assert.False(t, bytes.Equal(newCert, cert.Raw), "cert should not be here")
			// 		}
			// 	}
			// }
		}
	}

	// get the domain entries only if they are updated, from DB
	domainEntriesToWrite, err := GetDomainEntriesToWrite(updatedDomains, domainEntriesMap)
	require.NoError(t, err)

	// serialized the domainEntry -> key-value pair
	_, err = DeletemeSerializeUpdatedDomainEntries(domainEntriesToWrite)
	require.NoError(t, err)
}

// TestUpdateSameCertTwice: update the same certs twice, number of updates should be zero
func TestUpdateSameCertTwice(t *testing.T) {
	t.Skip() // deleteme
	certs := []*ctx509.Certificate{}
	// check if
	files, err := ioutil.ReadDir("./testdata/certs/")
	require.NoError(t, err, "ioutil.ReadDir")
	certChains := make([][]*ctx509.Certificate, len(files))
	for _, file := range files {
		cert, err := common.CTX509CertFromFile("./testdata/certs/" + file.Name())
		require.NoError(t, err, "projectCommon.CTX509CertFromFile")
		certs = append(certs, cert)
	}

	_, domainCertMap, domainCertChainMap := GetAffectedDomainAndCertMap(certs, certChains)

	domainEntriesMap := make(map[common.SHA256Output]*mapCommon.DomainEntry)

	// update domain entry with certs
	updatedDomains, err := UpdateDomainEntries(domainEntriesMap, domainCertMap, domainCertChainMap)
	require.NoError(t, err, "updateDomainEntries")

	// Length of updatedDomains should be that of the affected domains:
	assert.Equal(t, len(domainCertMap), len(updatedDomains), "updated domain should be 0")

	// update domain entry with same certs
	updatedDomains, err = UpdateDomainEntries(domainEntriesMap, domainCertMap, domainCertChainMap)
	require.NoError(t, err, "updateDomainEntries")

	// Now the length of updatedDomains should be zero.
	assert.Equal(t, 0, len(updatedDomains), "updated domain should be 0")
}
