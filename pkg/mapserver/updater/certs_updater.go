package updater

import (
	"context"
	"fmt"
	"time"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/domain"
	mapCommon "github.com/netsec-ethz/fpki/pkg/mapserver/common"
)

// TODO(yongzhe): make the list if size is already known.
// TODO(yongzhe): unit test for updateDomainEntryWithRPC and

type uniqueSet map[common.SHA256Output]struct{}
type uniqueStringSet map[string]struct{}

// UpdateDomainEntriesTableUsingCerts: Update the domain entries using the domain certificates
func (mapUpdater *MapUpdater) UpdateDomainEntriesTableUsingCerts(ctx context.Context, certs []*x509.Certificate,
	readerNum int) (int, error) {
	if len(certs) == 0 {
		return 0, nil
	}

	start := time.Now()
	// get the unique list of affected domains
	affectedDomainsMap, domainCertMap := getAffectedDomainAndCertMap(certs)
	end := time.Now()
	fmt.Println("(memory) time to process certs: ", end.Sub(start))

	// if no domain to update
	if len(affectedDomainsMap) == 0 {
		return 0, nil
	}

	start = time.Now()
	// retrieve (possibly)affected domain entries from db
	// It's possible that no records will be changed, because the certs are already recorded.
	domainEntriesMap, err := mapUpdater.retrieveAffectedDomainFromDB(ctx, affectedDomainsMap, readerNum)
	if err != nil {
		return 0, fmt.Errorf("UpdateDomainEntriesTableUsingCerts | retrieveAffectedDomainFromDB | %w", err)
	}
	end = time.Now()
	fmt.Println("(db)     time to retrieve domain entries: ", end.Sub(start))

	start = time.Now()
	// update the domain entries
	updatedDomains, err := updateDomainEntries(domainEntriesMap, domainCertMap)
	if err != nil {
		return 0, fmt.Errorf("UpdateDomainEntriesTableUsingCerts | updateDomainEntries | %w", err)
	}
	end = time.Now()
	fmt.Println("(db)     time to update domain entries: ", end.Sub(start))

	// if during this updates, no cert is added, directly return
	if len(updatedDomains) == 0 {
		return 0, nil
	}

	start = time.Now()
	// get the domain entries only if they are updated, from DB
	domainEntriesToWrite, err := getDomainEntriesToWrite(updatedDomains, domainEntriesMap)
	if err != nil {
		return 0, fmt.Errorf("UpdateDomainEntriesTableUsingCerts | getDomainEntriesToWrite | %w", err)
	}

	// serialized the domainEntry -> key-value pair
	keyValuePairs, updatedDomainNameHashes, err := serializeUpdatedDomainEntries(domainEntriesToWrite)
	if err != nil {
		return 0, fmt.Errorf("UpdateDomainEntriesTableUsingCerts | serializeUpdatedDomainEntries | %w", err)
	}
	end = time.Now()
	fmt.Println("(memory) time to process updated domains: ", end.Sub(start))

	start = time.Now()
	// commit changes to db
	num, err := mapUpdater.writeChangesToDB(ctx, keyValuePairs, updatedDomainNameHashes)
	if err != nil {
		return 0, fmt.Errorf("UpdateDomainEntriesTableUsingCerts | writeChangesToDB | %w", err)
	}
	end = time.Now()
	fmt.Println("(db)     time to write updated domain entries: ", end.Sub(start))

	return num, nil
}

// return affected domains.
// First return value: map of hashes of updated domain name. TODO(yongzhe): change this to a list maybe
// Second return value: "domain name" -> certs. So later, one can look through the map to decide which certs to
//     added to which domain.
func getAffectedDomainAndCertMap(certs []*x509.Certificate) (uniqueSet,
	map[string][]*x509.Certificate) {
	// unique list of the updated domains
	affectedDomainsMap := make(uniqueSet)

	// map to map "domain name" -> certs list(certs to be added to this domain).
	domainCertMap := make(map[string][]*x509.Certificate)

	// extract the affected domain of every certificates
	for _, cert := range certs {
		// get unique list of domain names
		domains := extractCertDomains(cert)
		if len(domains) == 0 {
			continue
		}

		// get affected domains
		affectedDomains := domain.ExtractAffectedDomains(domains)
		if len(affectedDomains) == 0 {
			continue
		}

		for _, domainName := range affectedDomains {
			var domainNameHash common.SHA256Output
			copy(domainNameHash[:], common.SHA256Hash([]byte(domainName)))

			affectedDomainsMap[domainNameHash] = struct{}{}
			_, ok := domainCertMap[domainName]
			if ok {
				domainCertMap[domainName] = append(domainCertMap[domainName], cert)
			} else {
				domainCertMap[domainName] = []*x509.Certificate{cert}
			}
		}
	}
	return affectedDomainsMap, domainCertMap
}

// update domain entries
func updateDomainEntries(domainEntries map[common.SHA256Output]*mapCommon.DomainEntry,
	certDomainMap map[string][]*x509.Certificate) (uniqueSet, error) {

	updatedDomainHash := make(uniqueSet)
	// read from previous map
	// the map records: domain - certs pair
	// Which domain will be affected by which certificates
	for domainName, certs := range certDomainMap {
		//iterStart := time.Now()
		for _, cert := range certs {
			var domainNameHash common.SHA256Output
			copy(domainNameHash[:], common.SHA256Hash([]byte(domainName)))
			// get domain entries
			domainEntry, ok := domainEntries[domainNameHash]
			// if domain entry does not exist in the db
			if !ok {
				// create an empty domain entry
				newDomainEntry := &mapCommon.DomainEntry{DomainName: domainName}
				domainEntries[domainNameHash] = newDomainEntry
				domainEntry = newDomainEntry
			}

			isUpdated := updateDomainEntry(domainEntry, cert)
			if isUpdated {
				// flag the updated domains
				updatedDomainHash[domainNameHash] = struct{}{}
			}

		}
	}

	return updatedDomainHash, nil
}

// updateDomainEntry: insert certificate into correct CAEntry
// return: if this domain entry is updated
func updateDomainEntry(domainEntry *mapCommon.DomainEntry, cert *x509.Certificate) bool {
	return domainEntry.AddCert(cert)
}

// getDomainEntriesToWrite: get updated domains, and extract the domain bytes
func getDomainEntriesToWrite(updatedDomain uniqueSet,
	domainEntries map[common.SHA256Output]*mapCommon.DomainEntry) (map[common.SHA256Output]*mapCommon.DomainEntry, error) {

	result := make(map[common.SHA256Output]*mapCommon.DomainEntry)
	for k := range updatedDomain {
		domainEntry, ok := domainEntries[k]
		if !ok {
			return nil, fmt.Errorf("getDomainEntriesToWrite | updated domain not recorded")
		}
		result[k] = domainEntry
		sortDomainEntry(domainEntry)
	}
	return result, nil
}

// serializeUpdatedDomainEntries: serialize the updated domains
func serializeUpdatedDomainEntries(domainEntriesMap map[common.SHA256Output]*mapCommon.DomainEntry) ([]db.KeyValuePair,
	[]common.SHA256Output, error) {
	result := make([]db.KeyValuePair, 0, len(domainEntriesMap))
	updatedDomainNameHashes := make([]common.SHA256Output, 0, len(domainEntriesMap))
	for domainNameHash, domainEntryBytes := range domainEntriesMap {
		domainBytes, err := mapCommon.SerializedDomainEntry(domainEntryBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("serializeUpdatedDomainEntries | SerializedDomainEntry | %w", err)
		}

		result = append(result, db.KeyValuePair{Key: domainNameHash, Value: domainBytes})
		updatedDomainNameHashes = append(updatedDomainNameHashes, domainNameHash)
	}
	return result, updatedDomainNameHashes, nil
}
