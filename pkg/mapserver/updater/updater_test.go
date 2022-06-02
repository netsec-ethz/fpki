package updater

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"testing"
	"time"

	projectCommon "github.com/netsec-ethz/fpki/pkg/common"

	ctX509 "github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/domain"
	"github.com/netsec-ethz/fpki/pkg/mapserver/logpicker"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//TestRPCAndPC: test if PC and RPC are correctly added
func TestRPCAndPC(t *testing.T) {
	start := time.Now()
	pcList, rpcList, err := logpicker.GetPCAndRPC("./testdata/domain_list/domains.txt", 0, 0, 0)
	require.NoError(t, err, "GetPCAndRPC error")
	end := time.Now()
	fmt.Println(end.Sub(start))

	start = time.Now()
	affectedDomainsMap, domainCertMap := getAffectedDomainAndCertMapPCAndRPC(rpcList, pcList)
	end = time.Now()
	fmt.Println(end.Sub(start))

	for _, pc := range pcList {
		subjectName := pc.Subject
		subjectNameHash := hex.EncodeToString(trie.Hasher([]byte(subjectName)))
		_, ok := affectedDomainsMap[subjectNameHash]
		assert.True(t, ok, "domain not found")

		for domainHash, newUpdate := range domainCertMap {
			if domainHash == subjectName {
				isFound := false
				for _, newPc := range newUpdate.pc {
					if newPc.Equal(*pc) {
						isFound = true
					}
				}
				assert.True(t, isFound, "new PC not included in domainCertMap")
			} else {
				for _, newPc := range newUpdate.pc {
					assert.False(t, newPc.Equal(*pc), "PC shouldn't be included in the map")
				}
			}
		}

	}

	for _, rpc := range rpcList {
		subjectName := rpc.Subject
		subjectNameHash := hex.EncodeToString(trie.Hasher([]byte(subjectName)))
		_, ok := affectedDomainsMap[subjectNameHash]
		assert.True(t, ok, "domain not found")

		for domainHash, newUpdate := range domainCertMap {
			if domainHash == subjectName {
				isFound := false
				for _, newRPC := range newUpdate.rpc {
					if newRPC.Equal(rpc) {
						isFound = true
					}
				}
				assert.True(t, isFound, "new RPC not included in domainCertMap")
			} else {
				for _, neRPC := range newUpdate.rpc {
					assert.False(t, neRPC.Equal(rpc), "RPC shouldn't be included in the map")
				}
			}
		}
	}
	assert.True(t, len(affectedDomainsMap) == len(domainCertMap))

	domainEntriesMap := make(map[string]*common.DomainEntry)

	updatedDomains, err := updateDomainEntriesWithRPCAndPC(domainEntriesMap, domainCertMap)
	require.NoError(t, err, "updateDomainEntriesWithRPCAndPC error")
	assert.Equal(t, len(updatedDomains), len(domainEntriesMap), "size of domainEntriesMap should be the size of updatedDomains")

	// check PC
	for _, pc := range pcList {
		subjectName := pc.Subject
		caName := pc.CAName
		subjectNameHash := hex.EncodeToString(trie.Hasher([]byte(subjectName)))

		for domainHash, domainEntry := range domainEntriesMap {
			switch {
			case domainHash == subjectNameHash:
				isFound := false
				for _, caList := range domainEntry.CAEntry {
					if caList.CAName == caName {
						isFound = true
						assert.True(t, caList.CurrentPC.Equal(*pc), "PC missing")
					} else {
						assert.False(t, caList.CurrentPC.Equal(*pc), "PC in wrong place")
					}
				}
				assert.True(t, isFound, "new PC not included in domainEntriesMap")
			case domainHash != subjectNameHash:
				for _, caList := range domainEntry.CAEntry {
					assert.False(t, caList.CurrentPC.Equal(*pc))
				}
			}
		}
	}

	// check RPC
	for _, rpc := range rpcList {
		subjectName := rpc.Subject
		caName := rpc.CAName
		subjectNameHash := hex.EncodeToString(trie.Hasher([]byte(subjectName)))

		for domainHash, domainEntry := range domainEntriesMap {
			switch {
			case domainHash == subjectNameHash:
				isFound := false
				for _, caList := range domainEntry.CAEntry {
					if caList.CAName == caName {
						isFound = true
						assert.True(t, caList.CurrentRPC.Equal(rpc), "RPC missing")
					} else {
						assert.False(t, caList.CurrentRPC.Equal(rpc), "RPC in wrong place")
					}
				}
				assert.True(t, isFound, "new RPC not included in domainEntriesMap")
			case domainHash != subjectNameHash:
				for _, caList := range domainEntry.CAEntry {
					assert.False(t, caList.CurrentRPC.Equal(rpc))
				}
			}
		}
	}
}

// TestCerts: test if certs are correctly added
func TestCerts(t *testing.T) {
	certs := []*ctX509.Certificate{}
	// check if
	files, err := ioutil.ReadDir("./testdata/certs/")
	require.NoError(t, err, "ioutil.ReadDir")
	for _, file := range files {
		cert, err := projectCommon.CTX509CertFromFile("./testdata/certs/" + file.Name())
		require.NoError(t, err, "projectCommon.CTX509CertFromFile")
		certs = append(certs, cert)
	}

	affectedDomainsMap, domainCertMap := getAffectedDomainAndCertMap(certs)

	for _, cert := range certs {
		domainNames := extractCertDomains(cert)

		affectedDomains := domain.ExtractAffectedDomains(domainNames)
		if len(affectedDomains) == 0 {
			continue
		}

		// check the correctness of affectedDomains
		for _, affectedDomain := range affectedDomains {
			_, ok := affectedDomainsMap[hex.EncodeToString(trie.Hasher([]byte(affectedDomain)))]
			assert.True(t, ok, "domain not found in affectedDomainsMap")
		}

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

	domainEntriesMap := make(map[string]*common.DomainEntry)
	updatedDomains, err := updateDomainEntries(domainEntriesMap, domainCertMap)
	require.NoError(t, err, "updateDomainEntries")

	assert.Equal(t, len(updatedDomains), len(affectedDomainsMap), "len(updatedDomains) should equals to len(affectedDomainsMap)")

	for _, cert := range certs {
		domainNames := extractCertDomains(cert)
		caName := cert.Issuer.CommonName

		affectedDomains := domain.ExtractAffectedDomains(domainNames)
		if len(affectedDomains) == 0 {
			continue
		}

		for _, domainName := range affectedDomains {
			domainHash := hex.EncodeToString(trie.Hasher([]byte(domainName)))

			for newDomainHash, domainEntry := range domainEntriesMap {
				if newDomainHash == domainHash {
					assert.True(t, domainEntry.DomainName == domainName)
					for _, calist := range domainEntry.CAEntry {
						if calist.CAName == caName {
							isFound := false
							for _, newCert := range calist.DomainCerts {
								if bytes.Equal(newCert, cert.Raw) {
									isFound = true
								}
							}
							assert.True(t, isFound, "cert not found")
						} else {
							for _, newCert := range calist.DomainCerts {
								assert.False(t, bytes.Equal(newCert, cert.Raw), "cert should not be here")
							}
						}
					}
				}
			}
		}
	}
}

// TestUpdateSameCertTwice: update the same certs twice, number of updates should be zero
func TestUpdateSameCertTwice(t *testing.T) {
	certs := []*ctX509.Certificate{}
	// check if
	files, err := ioutil.ReadDir("./testdata/certs/")
	require.NoError(t, err, "ioutil.ReadDir")
	for _, file := range files {
		cert, err := projectCommon.CTX509CertFromFile("./testdata/certs/" + file.Name())
		require.NoError(t, err, "projectCommon.CTX509CertFromFile")
		certs = append(certs, cert)
	}

	_, domainCertMap := getAffectedDomainAndCertMap(certs)

	domainEntriesMap := make(map[string]*common.DomainEntry)
	updatedDomains, err := updateDomainEntries(domainEntriesMap, domainCertMap)
	require.NoError(t, err, "updateDomainEntries")

	updatedDomains, err = updateDomainEntries(domainEntriesMap, domainCertMap)
	require.NoError(t, err, "updateDomainEntries")

	assert.Equal(t, 0, len(updatedDomains), "updated domain should be 0")
}

// TestUpdateSameRPCTwice: update the same RPC twice, number of updates should be zero
func TestUpdateSameRPCTwice(t *testing.T) {
	pcList, rpcList, err := logpicker.GetPCAndRPC("./testdata/domain_list/domains.txt", 0, 0, 0)
	require.NoError(t, err, "GetPCAndRPC error")

	_, domainCertMap := getAffectedDomainAndCertMapPCAndRPC(rpcList, pcList)

	domainEntriesMap := make(map[string]*common.DomainEntry)

	updatedDomains, err := updateDomainEntriesWithRPCAndPC(domainEntriesMap, domainCertMap)
	require.NoError(t, err, "updateDomainEntriesWithRPCAndPC error")
	assert.Equal(t, len(updatedDomains), len(domainEntriesMap), "size of domainEntriesMap should be the size of updatedDomains")

	updatedDomains, err = updateDomainEntriesWithRPCAndPC(domainEntriesMap, domainCertMap)
	require.NoError(t, err, "updateDomainEntriesWithRPCAndPC error")
	assert.Equal(t, 0, len(updatedDomains), "updated domain should be 0")
}

func includedIn(input []string, searchedString string) bool {
	for _, v := range input {
		if v == searchedString {
			return true
		}
	}
	return false
}
