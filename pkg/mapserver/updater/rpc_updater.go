package updater

import (
	"context"
	"fmt"

	projectCommon "github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/domain"
	"github.com/netsec-ethz/fpki/pkg/mapserver/common"
)

// newUpdates: structure for updates
type newUpdates struct {
	rpc []*projectCommon.RPC
	pc  []*projectCommon.SP
}

// UpdateDomainEntriesTableUsingRPCAndPC: update the domain entries table, given RPC and PC
func (mapUpdater *MapUpdater) UpdateDomainEntriesTableUsingRPCAndPC(ctx context.Context,
	rpc []*projectCommon.RPC, pc []*projectCommon.SP, readerNum int) (
	[]*db.KeyValuePair, int, error) {

	if len(rpc) == 0 && len(pc) == 0 {
		return nil, 0, nil
	}

	affectedDomainsMap, domainCertMap := getAffectedDomainAndCertMapPCAndRPC(rpc, pc)
	if len(affectedDomainsMap) == 0 {
		return nil, 0, nil
	}

	// retrieve (possibly)affected domain entries from db
	// It's possible that no records will be changed, because the certs are already recorded.
	domainEntriesMap, err := mapUpdater.retrieveAffectedDomainFromDB(ctx, affectedDomainsMap)
	if err != nil {
		return nil, 0, fmt.Errorf("UpdateDomainEntriesTableUsingRPCAndPC | retrieveAffectedDomainFromDB | %w", err)
	}

	// update the domain entries
	updatedDomains, err := updateDomainEntriesWithRPCAndPC(domainEntriesMap, domainCertMap)
	if err != nil {
		return nil, 0, fmt.Errorf("UpdateDomainEntriesTableUsingRPCAndPC | updateDomainEntriesWithRPCAndPC | %w", err)
	}

	// get the domain entries only if they are updated
	domainEntriesToWrite, err := getDomainEntriesToWrite(updatedDomains, domainEntriesMap)
	if err != nil {
		return nil, 0, fmt.Errorf("UpdateDomainEntriesTableUsingRPCAndPC | getDomainEntriesToWrite | %w", err)
	}

	// serialize the domainEntry -> key-value pair
	keyValuePairs, err := serializeUpdatedDomainEntries(domainEntriesToWrite)
	if err != nil {
		return nil, 0, fmt.Errorf("UpdateDomainEntriesTableUsingRPCAndPC | serializeUpdatedDomainEntries | %w", err)
	}

	// commit changes to db
	numOfWrites, err := mapUpdater.writeChangesToDB(ctx, keyValuePairs)
	if err != nil {
		return nil, 0, fmt.Errorf("UpdateDomainEntriesTableUsingRPCAndPC | serializeUpdatedDomainEntries | %w", err)
	}
	return keyValuePairs, numOfWrites, nil
}

// getAffectedDomainAndCertMapPCAndRPC: return a map of affected domains, and cert map
func getAffectedDomainAndCertMapPCAndRPC(rpc []*projectCommon.RPC, pc []*projectCommon.SP) (
	uniqueSet, map[string]*newUpdates) {

	// unique list of the updated domains
	affectedDomainsMap := make(uniqueSet)
	domainCertMap := make(map[string]*newUpdates)

	// deal with RPC
	for _, newRPC := range rpc {
		domainName := newRPC.Subject
		if !domain.IsValidDomain(domainName) {
			continue
		}

		var domainNameHash projectCommon.SHA256Output
		copy(domainNameHash[:], projectCommon.SHA256Hash([]byte(domainName)))

		// attach domain hash to unique map
		affectedDomainsMap[domainNameHash] = struct{}{}
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
		if !domain.IsValidDomain(domainName) {
			continue
		}

		var domainNameHash projectCommon.SHA256Output
		copy(domainNameHash[:], projectCommon.SHA256Hash([]byte(domainName)))

		affectedDomainsMap[domainNameHash] = struct{}{}
		certMapElement, ok := domainCertMap[domainName]
		if ok {
			certMapElement.pc = append(certMapElement.pc, newPC)
		} else {
			domainCertMap[domainName] = &newUpdates{pc: []*projectCommon.SP{newPC}}
		}
	}
	return affectedDomainsMap, domainCertMap
}

// updateDomainEntriesWithRPCAndPC: update domain entries
func updateDomainEntriesWithRPCAndPC(domainEntries map[projectCommon.SHA256Output]*common.DomainEntry,
	certDomainMap map[string]*newUpdates) (uniqueSet, error) {
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
				updatedDomainHash[domainNameHash] = struct{}{}
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
				updatedDomainHash[domainNameHash] = struct{}{}
			}
		}
	}
	return updatedDomainHash, nil
}

// updateDomainEntryWithRPC: insert RPC into correct CAEntry
func updateDomainEntryWithRPC(domainEntry *common.DomainEntry, rpc *projectCommon.RPC) bool {
	return domainEntry.AddRPC(rpc)
}

// updateDomainEntryWithPC: insert PC into correct CAEntry
func updateDomainEntryWithPC(domainEntry *common.DomainEntry, pc *projectCommon.SP) bool {
	return domainEntry.AddPC(pc)
}
