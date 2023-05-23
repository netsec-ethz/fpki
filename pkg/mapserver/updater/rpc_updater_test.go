package updater

import (
	"testing"

	projectCommon "github.com/netsec-ethz/fpki/pkg/common"

	"github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/logpicker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRPCAndPC: test getAffectedDomainAndCertMapPCAndRPC()
func TestRPCAndPC(t *testing.T) {
	// get PC and RPC
	pcList, rpcList, err := logpicker.GetPCAndRPC("./testdata/domain_list/domains.txt", 0, 0, 0)
	require.NoError(t, err, "GetPCAndRPC error")

	// add the affectedDomainsSet and domainCertMap
	affectedDomainsSet, domainCertMap := getAffectedDomainAndCertMapPCAndRPC(rpcList, pcList)

	// check affectedDomainsMap and domainCertMap are correct
	for _, pc := range pcList {
		subjectName := pc.Subject
		var subjectNameHash projectCommon.SHA256Output
		copy(subjectNameHash[:], projectCommon.SHA256Hash([]byte(subjectName)))

		assert.Contains(t, affectedDomainsSet, subjectNameHash)

		for domainHash, newUpdate := range domainCertMap {
			if domainHash == subjectName {
				assert.Contains(t, newUpdate.pc, pc)
			} else {
				assert.NotContains(t, newUpdate.pc, pc)
			}
		}
	}

	// check affectedDomainsMap and domainCertMap are correct
	for _, rpc := range rpcList {
		subjectName := rpc.Subject
		var subjectNameHash projectCommon.SHA256Output
		copy(subjectNameHash[:], projectCommon.SHA256Hash([]byte(subjectName)))

		_, ok := affectedDomainsSet[subjectNameHash]
		assert.True(t, ok, "domain not found")

		for domainHash, newUpdate := range domainCertMap {
			if domainHash == subjectName {
				assert.Contains(t, newUpdate.rpc, rpc)
			} else {
				assert.NotContains(t, newUpdate.rpc, rpc)
			}
		}
	}

	// length should be the same
	assert.Equal(t, len(affectedDomainsSet), len(domainCertMap))

}

// TestUpdateDomainEntriesWithRPCAndPC: test updateDomainEntriesWithRPCAndPC(), getDomainEntriesToWrite()
// and serializeUpdatedDomainEntries()
func TestUpdateDomainEntriesWithRPCAndPC(t *testing.T) {
	// // get PC and RPC
	// pcList, rpcList, err := logpicker.GetPCAndRPC("./testdata/domain_list/domains.txt", 0, 0, 0)
	// require.NoError(t, err, "GetPCAndRPC error")

	// // empty map(mock result from db).
	// domainEntriesMap := make(map[projectCommon.SHA256Output]*common.DomainEntry)

	// // add the affectedDomainsSet and domainCertMap
	// _, domainCertMap := getAffectedDomainAndCertMapPCAndRPC(rpcList, pcList)

	// updatedDomains, err := updateDomainEntriesWithRPCAndPC(domainEntriesMap, domainCertMap)
	// require.NoError(t, err)
	// assert.Equal(t, len(updatedDomains), len(domainEntriesMap), "size of domainEntriesMap should be the size of updatedDomains")

	// // check PC
	// for _, pc := range pcList {
	// 	subjectName := pc.Subject
	// 	caName := pc.CAName
	// 	var subjectNameHash projectCommon.SHA256Output
	// 	copy(subjectNameHash[:], projectCommon.SHA256Hash([]byte(subjectName)))

	// 	for domainHash, domainEntry := range domainEntriesMap {
	// 		switch {
	// 		case domainHash == subjectNameHash:
	// 			isFound := false
	// 			for _, caList := range domainEntry.Entries {
	// 				if caList.CAName == caName {
	// 					isFound = true
	// 					assert.True(t, caList.PCs.Equal(*pc), "PC missing")
	// 				} else {
	// 					assert.False(t, caList.PCs.Equal(*pc), "PC in wrong place")
	// 				}
	// 			}
	// 			assert.True(t, isFound, "new PC not included in domainEntriesMap")
	// 		case domainHash != subjectNameHash:
	// 			for _, caList := range domainEntry.Entries {
	// 				assert.False(t, caList.PCs.Equal(*pc))
	// 			}
	// 		}
	// 	}
	// }

	// // check RPC
	// for _, rpc := range rpcList {
	// 	subjectName := rpc.Subject
	// 	caName := rpc.CAName
	// 	var subjectNameHash projectCommon.SHA256Output
	// 	copy(subjectNameHash[:], projectCommon.SHA256Hash([]byte(subjectName)))

	// 	for domainHash, domainEntry := range domainEntriesMap {
	// 		switch {
	// 		case domainHash == subjectNameHash:
	// 			isFound := false
	// 			for _, caList := range domainEntry.Entries {
	// 				if caList.CAName == caName {
	// 					isFound = true
	// 					assert.True(t, caList.RPCs.Equal(rpc), "RPC missing")
	// 				} else {
	// 					assert.False(t, caList.RPCs.Equal(rpc), "RPC in wrong place")
	// 				}
	// 			}
	// 			assert.True(t, isFound, "new RPC not included in domainEntriesMap")
	// 		case domainHash != subjectNameHash:
	// 			for _, caList := range domainEntry.Entries {
	// 				assert.False(t, caList.RPCs.Equal(rpc))
	// 			}
	// 		}
	// 	}
	// }

	// // get the domain entries only if they are updated
	// domainEntriesToWrite, err := GetDomainEntriesToWrite(updatedDomains, domainEntriesMap)
	// require.NoError(t, err)

	// // serialize the domainEntry -> key-value pair
	// _, err = SerializeUpdatedDomainEntries(domainEntriesToWrite)
	// require.NoError(t, err)
}

// TestUpdateSameRPCTwice: update the same RPC twice, number of updates should be zero
func TestUpdateSameRPCTwice(t *testing.T) {
	t.Skip() // deleteme

	pcList, rpcList, err := logpicker.GetPCAndRPC("./testdata/domain_list/domains.txt", 0, 0, 0)
	require.NoError(t, err, "GetPCAndRPC error")

	_, domainCertMap := getAffectedDomainAndCertMapPCAndRPC(rpcList, pcList)

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
