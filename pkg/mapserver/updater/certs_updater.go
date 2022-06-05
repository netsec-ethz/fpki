package updater

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/domain"
	mapCommon "github.com/netsec-ethz/fpki/pkg/mapserver/common"
)

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

	fmt.Println("number of affected domains: ", len(affectedDomainsMap))

	start := time.Now()
	// retrieve (possibly)affected domain entries from db
	// It's possible that no records will be changed, because the certs are already recorded.
	domainEntriesMap, err := mapUpdater.retrieveAffectedDomainFromDB(ctx, affectedDomainsMap, readerNum)
	if err != nil {
		return 0, fmt.Errorf("UpdateDomainEntriesUsingCerts | retrieveAffectedDomainFromDB | %w", err)
	}
	end := time.Now()
	fmt.Println("---time to retrieveAffectedDomainFromDB:   ", end.Sub(start))

	start = time.Now()
	// update the domain entries
	updatedDomains, err := updateDomainEntries(domainEntriesMap, domainCertMap)
	if err != nil {
		return 0, fmt.Errorf("UpdateDomainEntriesUsingCerts | updateDomainEntries | %w", err)
	}
	end = time.Now()
	fmt.Println("---time to updateDomainEntries:   ", end.Sub(start))

	// if during this updates, no cert is added, directly return
	if len(updatedDomains) == 0 {
		return 0, nil
	}

	start = time.Now()
	// get the domain entries only if they are updated, from DB
	domainEntriesToWrite, err := getDomainEntriesToWrite(updatedDomains, domainEntriesMap)
	if err != nil {
		return 0, fmt.Errorf("UpdateDomainEntriesUsingCerts | domainEntriesToWrite | %w", err)
	}
	end = time.Now()
	fmt.Println("---time to getDomainEntriesToWrite:   ", end.Sub(start))

	// serialised the domainEntry -> key-value pair
	start = time.Now()
	keyValuePairs, updatedDomainNameHashes, err := serializeUpdatedDomainEntries(domainEntriesToWrite)
	if err != nil {
		return 0, fmt.Errorf("UpdateDomainEntriesUsingCerts | serializeUpdatedDomainEntries | %w", err)
	}
	end = time.Now()
	fmt.Println("---time to serializeUpdatedDomainEntries:   ", end.Sub(start))

	// commit changes to db
	return mapUpdater.writeChangesToDB(ctx, keyValuePairs, updatedDomainNameHashes)
}

// return affected domains.
// First return value: map of hashes of updated domain name. TODO(yongzhe): change this to a list maybe
// Second return value: "domain name" -> certs. So later, one can look through the map to decide which certs to
//     added to which domain.
func getAffectedDomainAndCertMap(certs []*x509.Certificate, parser *domain.DomainParser) (map[common.SHA256Output]byte, map[string][]*x509.Certificate) {
	// unique list of the updated domains
	affectedDomainsMap := make(map[common.SHA256Output]byte)

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

			affectedDomainsMap[domainNameHash] = 1
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

// get domain from cert:
// 1. Subject name
// 2. SANs
func extractCertDomains(cert *x509.Certificate) []string {
	domains := make(map[string]byte)
	if len(cert.Subject.CommonName) != 0 {
		domains[cert.Subject.CommonName] = 1
	}

	for _, dnsName := range cert.DNSNames {
		domains[dnsName] = 1
	}

	result := []string{}
	for k := range domains {
		result = append(result, k)
	}
	return result
}

// update domain entries
func updateDomainEntries(domainEntries map[common.SHA256Output]*mapCommon.DomainEntry,
	certDomainMap map[string][]*x509.Certificate) (map[common.SHA256Output]byte, error) {

	updatedDomainHash := make(map[common.SHA256Output]byte)
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
			// if domain entry exists in the db
			if ok {
				isUpdated := updateDomainEntry(domainEntry, cert)
				if isUpdated {
					// flag the updated domains
					updatedDomainHash[domainNameHash] = 1
				}
			} else {
				// create an empty domain entry
				newDomainEntry := &mapCommon.DomainEntry{DomainName: domainName}
				domainEntries[domainNameHash] = newDomainEntry
				isUpdated := updateDomainEntry(newDomainEntry, cert)
				if isUpdated {
					// flag the updated domains
					updatedDomainHash[domainNameHash] = 1
				}
			}
		}
		/*
			iterEnd := time.Now()
			if iterEnd.Sub(iterStart) > time.Millisecond {
				fmt.Println(iterEnd.Sub(iterStart), " ", len(certs), " ", domainName)
				for _, cert := range certs {
					fmt.Println()
					fmt.Println(cert.Subject.CommonName)
					for _, name := range cert.DNSNames {
						fmt.Println(name)
					}
				}
			}*/
	}

	return updatedDomainHash, nil
}

// insert certificate into correct CAEntry
func updateDomainEntry(domainEntry *mapCommon.DomainEntry, cert *x509.Certificate) bool {
	caName := cert.Issuer.CommonName
	isFound := false
	isUpdated := false

ca_entry_loop:
	// iterate CAEntry list, find if the target CA list exists
	for i := range domainEntry.CAEntry {
		if domainEntry.CAEntry[i].CAName == caName {
			isFound = true
			// check whether this certificate is already registered
			for _, certRaw := range domainEntry.CAEntry[i].DomainCerts {
				if bytes.Equal(certRaw, cert.Raw) {
					break ca_entry_loop
				}
			}
			// if not, append the raw of the certificate
			domainEntry.CAEntry[i].DomainCerts = append(domainEntry.CAEntry[i].DomainCerts, cert.Raw)

			isUpdated = true
			break
		}
	}

	// if CA list is not found
	if !isFound {
		// add a new CA list
		domainEntry.CAEntry = append(domainEntry.CAEntry, mapCommon.CAEntry{
			DomainCerts: [][]byte{cert.Raw},
			CAName:      caName,
			CAHash:      common.SHA256Hash([]byte(caName))})
		isUpdated = true
	}

	return isUpdated
}

// get updated domains, and extract the corresponding domain bytes
func getDomainEntriesToWrite(updatedDomain map[common.SHA256Output]byte,
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
		domainBytes, err := mapCommon.SerialisedDomainEntry(domainEntryBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("serializeUpdatedDomainEntries | SerializeDomainEntry | %w", err)
		}

		result = append(result, db.KeyValuePair{Key: domainNameHash, Value: domainBytes})
		updatedDomainNameHashes = append(updatedDomainNameHashes, domainNameHash)
	}
	return result, updatedDomainNameHashes, nil
}

// sort domain entries
func sortDomainEntry(domainEntry *mapCommon.DomainEntry) {
	// sort CA entries
	sort.Slice(domainEntry.CAEntry, func(j, k int) bool {
		switch {
		case len(domainEntry.CAEntry[j].CAHash) < len(domainEntry.CAEntry[k].CAHash):
			return true
		case len(domainEntry.CAEntry[j].CAHash) > len(domainEntry.CAEntry[k].CAHash):
			return false
		}
		return bytes.Compare(domainEntry.CAEntry[j].CAHash, domainEntry.CAEntry[k].CAHash) == -1
	})

	// sort individual list
	for i := range domainEntry.CAEntry {
		sort.Slice(domainEntry.CAEntry[i].DomainCerts, func(j, k int) bool {
			switch {
			case len(domainEntry.CAEntry[i].DomainCerts[j]) < len(domainEntry.CAEntry[i].DomainCerts[k]):
				return true
			case len(domainEntry.CAEntry[i].DomainCerts[j]) > len(domainEntry.CAEntry[i].DomainCerts[k]):
				return false
			}
			return bytes.Compare(domainEntry.CAEntry[i].DomainCerts[j], domainEntry.CAEntry[i].DomainCerts[k]) == -1
		})
	}
}
