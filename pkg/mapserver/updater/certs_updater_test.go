package updater

import (
	"bytes"
	"io/ioutil"
	"testing"

	projectCommon "github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/domain"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCerts: test UpdateDomainEntriesUsingCerts
// This test tests the individual functions of the UpdateDomainEntriesUsingCerts()
func TestUpdateDomainEntriesUsingCerts(t *testing.T) {
	parser, err := domain.NewDomainParser()
	require.NoError(t, err)

	certs := []*x509.Certificate{}

	// load test certs
	files, err := ioutil.ReadDir("./testdata/certs/")
	require.NoError(t, err, "ioutil.ReadDir")
	for _, file := range files {
		cert, err := projectCommon.CTX509CertFromFile("./testdata/certs/" + file.Name())
		require.NoError(t, err, "projectCommon.CTX509CertFromFile")
		certs = append(certs, cert)
	}

	// get affected domain map and domain cert map
	affectedDomainsMap, domainCertMap := getAffectedDomainAndCertMap(certs, parser)

	// test if all the certs are correctly added to the affectedDomainsMap and domainCertMap
	for _, cert := range certs {
		// get common name and SAN of the certificate
		domainNames := extractCertDomains(cert)

		// get the valid domain name from domainNames list
		affectedDomains := parser.ExtractAffectedDomains(domainNames)
		if len(affectedDomains) == 0 {
			// if cert does not have a valid domain name
			continue
		}

		// check the affected domain is correctly added to the affectedDomains
		for _, affectedDomain := range affectedDomains {
			var affectedNameHash projectCommon.SHA256Output
			copy(affectedNameHash[:], projectCommon.SHA256Hash([]byte(affectedDomain)))

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
	domainEntriesMap := make(map[projectCommon.SHA256Output]*common.DomainEntry)
	updatedDomains, err := updateDomainEntries(domainEntriesMap, domainCertMap)
	require.NoError(t, err, "updateDomainEntries")

	assert.Equal(t, len(updatedDomains), len(affectedDomainsMap), "len(updatedDomains) should equals to len(affectedDomainsMap)")

	// check if domainEntriesMap is correctly updated
	for _, cert := range certs {
		domainNames := extractCertDomains(cert)
		caName := cert.Issuer.CommonName

		// check if this cert has valid name
		affectedDomains := parser.ExtractAffectedDomains(domainNames)
		if len(affectedDomains) == 0 {
			continue
		}

		// check domainEntriesMap
		for _, domainName := range affectedDomains {
			var domainHash projectCommon.SHA256Output
			copy(domainHash[:], projectCommon.SHA256Hash([]byte(domainName)))

			domainEntry, ok := domainEntriesMap[domainHash]
			assert.True(t, ok, "domainEntriesMap error")

			// check domain name is correct
			assert.True(t, domainEntry.DomainName == domainName)
			for _, caList := range domainEntry.CAEntry {
				if caList.CAName == caName {
					isFound := false
					for _, newCert := range caList.DomainCerts {
						if bytes.Equal(newCert, cert.Raw) {
							isFound = true
						}
					}
					assert.True(t, isFound, "cert not found")
				} else {
					for _, newCert := range caList.DomainCerts {
						assert.False(t, bytes.Equal(newCert, cert.Raw), "cert should not be here")
					}
				}
			}
		}
	}

	// get the domain entries only if they are updated, from DB
	domainEntriesToWrite, err := getDomainEntriesToWrite(updatedDomains, domainEntriesMap)
	require.NoError(t, err)

	// serialized the domainEntry -> key-value pair
	_, _, err = serializeUpdatedDomainEntries(domainEntriesToWrite)
	require.NoError(t, err)
}

// TestUpdateSameCertTwice: update the same certs twice, number of updates should be zero
func TestUpdateSameCertTwice(t *testing.T) {
	parser, err := domain.NewDomainParser()
	require.NoError(t, err)

	certs := []*x509.Certificate{}
	// check if
	files, err := ioutil.ReadDir("./testdata/certs/")
	require.NoError(t, err, "ioutil.ReadDir")
	for _, file := range files {
		cert, err := projectCommon.CTX509CertFromFile("./testdata/certs/" + file.Name())
		require.NoError(t, err, "projectCommon.CTX509CertFromFile")
		certs = append(certs, cert)
	}

	_, domainCertMap := getAffectedDomainAndCertMap(certs, parser)

	domainEntriesMap := make(map[projectCommon.SHA256Output]*common.DomainEntry)

	// update domain entry with certs
	updatedDomains, err := updateDomainEntries(domainEntriesMap, domainCertMap)
	require.NoError(t, err, "updateDomainEntries")

	// update domain entry with same certs
	updatedDomains, err = updateDomainEntries(domainEntriesMap, domainCertMap)
	require.NoError(t, err, "updateDomainEntries")

	// length of updatedDomains should be zero.
	assert.Equal(t, 0, len(updatedDomains), "updated domain should be 0")
}
