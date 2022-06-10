package updater

import (
	"bytes"
	"context"
	"fmt"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/domain"
	mapCommon "github.com/netsec-ethz/fpki/pkg/mapserver/common"
)

type uniqueSet map[common.SHA256Output]struct{}
type uniqueStringSet map[string]struct{}

var empty struct{}

// UpdateDomainEntriesUsingCerts: Update the domain entries using the domain certificates
func (mapUpdater *MapUpdater) UpdateDomainEntriesUsingCerts(ctx context.Context, certs []*x509.Certificate, readerNum int) (int, error) {
	if len(certs) == 0 {
		return 0, nil
	}

	// get the unique list of affected domains
	affectedDomainsMap, domainCertMap := getAffectedDomainAndCertMap(certs, mapUpdater.domainParser)

	// if no domain to update
	if len(affectedDomainsMap) == 0 {
		return 0, nil
	}

	// retrieve (possibly)affected domain entries from db
	// It's possible that no records will be changed, because the certs are already recorded.
	domainEntriesMap, err := mapUpdater.retrieveAffectedDomainFromDB(ctx, affectedDomainsMap, readerNum)
	if err != nil {
		return 0, fmt.Errorf("UpdateDomainEntriesUsingCerts | retrieveAffectedDomainFromDB | %w", err)
	}

	// update the domain entries
	updatedDomains, err := updateDomainEntries(domainEntriesMap, domainCertMap)
	if err != nil {
		return 0, fmt.Errorf("UpdateDomainEntriesUsingCerts | updateDomainEntries | %w", err)
	}

	// if during this updates, no cert is added, directly return
	if len(updatedDomains) == 0 {
		return 0, nil
	}

	// get the domain entries only if they are updated, from DB
	domainEntriesToWrite, err := getDomainEntriesToWrite(updatedDomains, domainEntriesMap)
	if err != nil {
		return 0, fmt.Errorf("UpdateDomainEntriesUsingCerts | domainEntriesToWrite | %w", err)
	}

	// serialized the domainEntry -> key-value pair
	keyValuePairs, updatedDomainNameHashes, err := serializeUpdatedDomainEntries(domainEntriesToWrite)
	if err != nil {
		return 0, fmt.Errorf("UpdateDomainEntriesUsingCerts | serializeUpdatedDomainEntries | %w", err)
	}

	// commit changes to db
	return mapUpdater.writeChangesToDB(ctx, keyValuePairs, updatedDomainNameHashes)
}

// return affected domains.
// First return value: map of hashes of updated domain name. TODO(yongzhe): change this to a list maybe
// Second return value: "domain name" -> certs. So later, one can look through the map to decide which certs to
//     added to which domain.
func getAffectedDomainAndCertMap(certs []*x509.Certificate, parser *domain.DomainParser) (uniqueSet, map[string][]*x509.Certificate) {
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
		affectedDomains := parser.ExtractAffectedDomains(domains)
		if len(affectedDomains) == 0 {
			continue
		}

		for _, domainName := range affectedDomains {
			var domainNameHash common.SHA256Output
			copy(domainNameHash[:], common.SHA256Hash([]byte(domainName)))

			affectedDomainsMap[domainNameHash] = empty
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
				updatedDomainHash[domainNameHash] = empty
			}

		}
	}

	return updatedDomainHash, nil
}

// updateDomainEntry: insert certificate into correct CAEntry
func updateDomainEntry(domainEntry *mapCommon.DomainEntry, cert *x509.Certificate) bool {
	caName := cert.Issuer.CommonName
	isFound := false

	// iterate CAEntry list, find if the target CA list exists
	for i := range domainEntry.CAEntry {
		if domainEntry.CAEntry[i].CAName == caName {
			isFound = true
			// check whether this certificate is already registered
			for _, certRaw := range domainEntry.CAEntry[i].DomainCerts {
				if bytes.Equal(certRaw, cert.Raw) {
					return false
				}
			}
			// if not, append the raw of the certificate
			domainEntry.CAEntry[i].DomainCerts = append(domainEntry.CAEntry[i].DomainCerts, cert.Raw)

			return true
		}
	}

	// if CA list is not found
	if !isFound {
		// add a new CA list
		domainEntry.CAEntry = append(domainEntry.CAEntry, mapCommon.CAEntry{
			DomainCerts: [][]byte{cert.Raw},
			CAName:      caName,
			CAHash:      common.SHA256Hash([]byte(caName))})
		return true
	}

	return false
}

// get updated domains, and extract the corresponding domain bytes
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

// serialize the updated domains
func serializeUpdatedDomainEntries(domainEntriesMap map[common.SHA256Output]*mapCommon.DomainEntry) ([]db.KeyValuePair, []common.SHA256Output, error) {
	result := []db.KeyValuePair{}
	updatedDomainNameHashes := []common.SHA256Output{}
	for domainNameHash, domainEntryBytes := range domainEntriesMap {
		domainBytes, err := mapCommon.SerializedDomainEntry(domainEntryBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("serializeUpdatedDomainEntries | SerializeDomainEntry | %w", err)
		}

		result = append(result, db.KeyValuePair{Key: domainNameHash, Value: domainBytes})
		updatedDomainNameHashes = append(updatedDomainNameHashes, domainNameHash)
	}
	return result, updatedDomainNameHashes, nil
}
