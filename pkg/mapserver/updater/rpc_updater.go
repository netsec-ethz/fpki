package updater

import (
	"context"
	"fmt"

	projectCommon "github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/domain"
	"github.com/netsec-ethz/fpki/pkg/mapserver/common"
)

// newUpdates: structure for updates
type newUpdates struct {
	rpc []*projectCommon.RPC
	pc  []*projectCommon.PC
}

// UpdateDomainEntriesUsingRPCAndPC: update the domain entries table, given RPC and PC
func (mapUpdater *MapUpdater) UpdateDomainEntriesUsingRPCAndPC(ctx context.Context, rpc []*projectCommon.RPC, pc []*projectCommon.PC, readerNum int) (int, error) {
	if len(rpc) == 0 && len(pc) == 0 {
		return 0, nil
	}

	affectedDomainsMap, domainCertMap := getAffectedDomainAndCertMapPCAndRPC(rpc, pc, mapUpdater.domainParser)
	if len(affectedDomainsMap) == 0 {
		return 0, nil
	}

	// retrieve (possibly)affected domain entries from db
	// It's possible that no records will be changed, because the certs are already recorded.
	domainEntriesMap, err := mapUpdater.retrieveAffectedDomainFromDB(ctx, affectedDomainsMap, readerNum)
	if err != nil {
		return 0, fmt.Errorf("UpdateDomainEntriesUsingRPCAndPC | retrieveAffectedDomainFromDB | %w", err)
	}

	// update the domain entries
	updatedDomains, err := updateDomainEntriesWithRPCAndPC(domainEntriesMap, domainCertMap)
	if err != nil {
		return 0, fmt.Errorf("UpdateDomainEntriesUsingRPCAndPC | updateDomainEntriesWithRPCAndPC | %w", err)
	}

	// get the domain entries only if they are updated
	domainEntriesToWrite, err := getDomainEntriesToWrite(updatedDomains, domainEntriesMap)
	if err != nil {
		return 0, fmt.Errorf("UpdateDomainEntriesUsingRPCAndPC | getDomainEntriesToWrite | %w", err)
	}

	// serialize the domainEntry -> key-value pair
	keyValuePairs, updatedDomainNames, err := serializeUpdatedDomainEntries(domainEntriesToWrite)
	if err != nil {
		return 0, fmt.Errorf("UpdateDomainEntriesUsingRPCAndPC | serializeUpdatedDomainEntries | %w", err)
	}

	// commit changes to db
	return mapUpdater.writeChangesToDB(ctx, keyValuePairs, updatedDomainNames)
}

// getAffectedDomainAndCertMapPCAndRPC: return a map of affected domains, and cert map
func getAffectedDomainAndCertMapPCAndRPC(rpc []*projectCommon.RPC, pc []*projectCommon.PC, domainParser *domain.DomainParser) (uniqueSet, map[string]*newUpdates) {
	// unique list of the updated domains
	affectedDomainsMap := make(uniqueSet)
	domainCertMap := make(map[string]*newUpdates)

	// deal with RPC
	for _, newRPC := range rpc {
		domainName := newRPC.Subject
		if !domainParser.IsValidDomain(domainName) {
			continue
		}

		var domainNameHash projectCommon.SHA256Output
		copy(domainNameHash[:], projectCommon.SHA256Hash([]byte(domainName)))

		// attach domain hash to unique map
		affectedDomainsMap[domainNameHash] = empty
		certMapElement, ok := domainCertMap[domainName]
		if ok {
			certMapElement.rpc = append(certMapElement.rpc, newRPC)
		} else {
			domainCertMap[domainName] = &newUpdates{rpc: []*projectCommon.RPC{newRPC}}
		}
	}

	// deal with PC
	for _, newPC := range pc {
		domainName := newPC.Subject
		if !domainParser.IsValidDomain(domainName) {
			continue
		}

		var domainNameHash projectCommon.SHA256Output
		copy(domainNameHash[:], projectCommon.SHA256Hash([]byte(domainName)))

		affectedDomainsMap[domainNameHash] = empty
		certMapElement, ok := domainCertMap[domainName]
		if ok {
			certMapElement.pc = append(certMapElement.pc, newPC)
		} else {
			domainCertMap[domainName] = &newUpdates{pc: []*projectCommon.PC{newPC}}
		}
	}
	return affectedDomainsMap, domainCertMap
}

// updateDomainEntriesWithRPCAndPC: update domain entries
func updateDomainEntriesWithRPCAndPC(domainEntries map[projectCommon.SHA256Output]*common.DomainEntry, certDomainMap map[string]*newUpdates) (uniqueSet, error) {
	updatedDomainHash := make(uniqueSet)
	// read from previous map
	// the map records: domain - certs pair
	// Which domain will be affected by which certificates
	for domainName, updates := range certDomainMap {
		for _, rpc := range updates.rpc {
			var domainNameHash projectCommon.SHA256Output
			copy(domainNameHash[:], projectCommon.SHA256Hash([]byte(domainName)))

			// get domain entries
			domainEntry, ok := domainEntries[domainNameHash]
			// if domain entry exists in the db
			if !ok {
				// create an empty domain entry
				newDomainEntry := &common.DomainEntry{DomainName: domainName}
				domainEntries[domainNameHash] = newDomainEntry
				domainEntry = newDomainEntry
			}

			isUpdated := updateDomainEntryWithRPC(domainEntry, rpc)
			if isUpdated {
				// flag the updated domains
				updatedDomainHash[domainNameHash] = empty
			}
		}

		for _, pc := range updates.pc {
			var domainNameHash projectCommon.SHA256Output
			copy(domainNameHash[:], projectCommon.SHA256Hash([]byte(domainName)))

			// get domain entries
			domainEntry, ok := domainEntries[domainNameHash]
			// if domain entry exists in the db
			if !ok {
				// create an empty domain entry
				newDomainEntry := &common.DomainEntry{DomainName: domainName}
				domainEntries[domainNameHash] = newDomainEntry
				domainEntry = newDomainEntry
			}

			isUpdated := updateDomainEntryWithPC(domainEntry, pc)
			if isUpdated {
				// flag the updated domains
				updatedDomainHash[domainNameHash] = empty
			}
		}
	}
	return updatedDomainHash, nil
}

// updateDomainEntryWithRPC: insert certificate into correct CAEntry
func updateDomainEntryWithRPC(domainEntry *common.DomainEntry, rpc *projectCommon.RPC) bool {
	caName := rpc.CAName
	isFound := false
	isUpdated := false

	// iterate CAEntry list, find if the target CA list exists
	for i := range domainEntry.CAEntry {
		if domainEntry.CAEntry[i].CAName == caName {
			isFound = true
			// check whether this certificate is already registered
			if !domainEntry.CAEntry[i].CurrentRPC.Equal(rpc) {
				isUpdated = true
				domainEntry.CAEntry[i].CurrentRPC = *rpc
			}
			break
		}
	}

	// if CA list is not found
	if !isFound {
		// add a new CA list
		domainEntry.CAEntry = append(domainEntry.CAEntry, common.CAEntry{
			CAName:     caName,
			CAHash:     projectCommon.SHA256Hash([]byte(caName)),
			CurrentRPC: *rpc,
		})
		isUpdated = true
	}
	return isUpdated
}

// updateDomainEntryWithPC: insert pc into correct CAEntry
func updateDomainEntryWithPC(domainEntry *common.DomainEntry, pc *projectCommon.PC) bool {
	caName := pc.CAName
	isFound := false
	isUpdated := false

	// iterate CAEntry list, find if the target CA list exists
	for i := range domainEntry.CAEntry {
		if domainEntry.CAEntry[i].CAName == caName {
			isFound = true
			// check whether this certificate is already registered
			if !domainEntry.CAEntry[i].CurrentPC.Equal(*pc) {
				isUpdated = true
				domainEntry.CAEntry[i].CurrentPC = *pc
			}
			break
		}
	}

	// if CA list is not found
	if !isFound {
		// add a new CA list
		domainEntry.CAEntry = append(domainEntry.CAEntry, common.CAEntry{
			CAName:    caName,
			CAHash:    projectCommon.SHA256Hash([]byte(caName)),
			CurrentPC: *pc,
		})
		isUpdated = true
	}
	return isUpdated
}
