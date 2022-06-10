package updater

import (
	"testing"

	projectCommon "github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/domain"

	"github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/logpicker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//TestRPCAndPC: test UpdateDomainEntriesUsingRPCAndPC()
//This test tests the sub-functions from the UpdateDomainEntriesUsingRPCAndPC(), except for the db-related sub-functions
func TestRPCAndPC(t *testing.T) {
	parser, err := domain.NewDomainParser()
	require.NoError(t, err)

	// get PC and RPC
	pcList, rpcList, err := logpicker.GetPCAndRPC("./testdata/domain_list/domains.txt", 0, 0, 0)
	require.NoError(t, err, "GetPCAndRPC error")

	// add the affectedDomainsMap and domainCertMap
	affectedDomainsMap, domainCertMap := getAffectedDomainAndCertMapPCAndRPC(rpcList, pcList, parser)

	// check affectedDomainsMap and domainCertMap are correct
	for _, pc := range pcList {
		subjectName := pc.Subject
		var subjectNameHash projectCommon.SHA256Output
		copy(subjectNameHash[:], projectCommon.SHA256Hash([]byte(subjectName)))

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

	// check affectedDomainsMap and domainCertMap are correct
	for _, rpc := range rpcList {
		subjectName := rpc.Subject
		var subjectNameHash projectCommon.SHA256Output
		copy(subjectNameHash[:], projectCommon.SHA256Hash([]byte(subjectName)))

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

	domainEntriesMap := make(map[projectCommon.SHA256Output]*common.DomainEntry)

	updatedDomains, err := updateDomainEntriesWithRPCAndPC(domainEntriesMap, domainCertMap)
	require.NoError(t, err, "updateDomainEntriesWithRPCAndPC error")
	assert.Equal(t, len(updatedDomains), len(domainEntriesMap), "size of domainEntriesMap should be the size of updatedDomains")

	// check PC
	for _, pc := range pcList {
		subjectName := pc.Subject
		caName := pc.CAName
		var subjectNameHash projectCommon.SHA256Output
		copy(subjectNameHash[:], projectCommon.SHA256Hash([]byte(subjectName)))

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
		var subjectNameHash projectCommon.SHA256Output
		copy(subjectNameHash[:], projectCommon.SHA256Hash([]byte(subjectName)))

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

	// get the domain entries only if they are updated
	domainEntriesToWrite, err := getDomainEntriesToWrite(updatedDomains, domainEntriesMap)
	require.NoError(t, err)

	// serialize the domainEntry -> key-value pair
	_, _, err = serializeUpdatedDomainEntries(domainEntriesToWrite)
	require.NoError(t, err)
}

// TestUpdateSameRPCTwice: update the same RPC twice, number of updates should be zero
func TestUpdateSameRPCTwice(t *testing.T) {
	pcList, rpcList, err := logpicker.GetPCAndRPC("./testdata/domain_list/domains.txt", 0, 0, 0)
	require.NoError(t, err, "GetPCAndRPC error")

	parser, err := domain.NewDomainParser()
	require.NoError(t, err)

	_, domainCertMap := getAffectedDomainAndCertMapPCAndRPC(rpcList, pcList, parser)

	domainEntriesMap := make(map[projectCommon.SHA256Output]*common.DomainEntry)

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
