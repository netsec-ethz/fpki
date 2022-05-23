package updater

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/domain"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
)

func UpdateDomainEntriesUsingCerts(certs []*x509.Certificate, dbConn db.Conn, readerNum int) (int, error) {
	if len(certs) == 0 {
		return 0, nil
	}

	affectedDomainsMap, domainCertMap := getAffectedDomainAndCertMap(certs)

	if len(affectedDomainsMap) == 0 {
		return 0, nil
	}

	// retrieve (possibly)affected domain entries from db
	// It's possible that no records will be changed, because the certs are already recorded.
	domainEntriesMap, err := retrieveAffectedDomainFromDB(affectedDomainsMap, dbConn, readerNum)
	if err != nil {
		return 0, fmt.Errorf("UpdateDomainEntries | retrieveAffectedDomainFromDB | %w", err)
	}

	// update the domain entries
	updatedDomains, err := updateDomainEntries(domainEntriesMap, domainCertMap)
	if err != nil {
		return 0, fmt.Errorf("UpdateDomainEntries | updateDomainEntries | %w", err)
	}

	if len(updatedDomains) == 0 {
		return 0, nil
	}

	// get the domain entries only if they are updated
	domainEntriesToWrite, err := getDomainEntriesToWrite(updatedDomains, domainEntriesMap)
	if err != nil {
		return 0, fmt.Errorf("writeChangesToDB | domainEntriesToWrite | %w", err)
	}

	// serialise the domainEntry -> key-value pair
	keyValuePairs, updatedDomainNames, err := serialiseUpdatedDomainEntries(domainEntriesToWrite)
	if err != nil {
		return 0, fmt.Errorf("writeChangesToDB | serialiseUpdatedDomainEntries | %w", err)
	}

	// commit changes to db
	return writeChangesToDB(keyValuePairs, updatedDomainNames, dbConn)
}

func getAffectedDomainAndCertMap(certs []*x509.Certificate) (map[string]byte, map[string][]*x509.Certificate) {
	// unique list of the updated domains
	affectedDomainsMap := make(map[string]byte)
	domainCertMap := make(map[string][]*x509.Certificate)

	// extract the affected domain of every certificates
	for _, cert := range certs {
		// get unique list of domain names
		domains := extractCertDomains(cert)
		if len(domains) == 0 {
			continue
		}

		// get affected domains
		affectedDomains := domain.ExtractEffectedDomains(domains)
		if len(affectedDomains) == 0 {
			continue
		}

		for _, domainName := range affectedDomains {
			domainNameHash := hex.EncodeToString(trie.Hasher([]byte(domainName)))

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
	if len(cert.DNSNames) != 0 {
		for _, dnsName := range cert.DNSNames {
			domains[dnsName] = 1
		}
	}

	result := []string{}
	for k := range domains {
		result = append(result, k)
	}
	return result
}

// update domain entries
func updateDomainEntries(domainEntries map[string]*common.DomainEntry, certDomainMap map[string][]*x509.Certificate) (map[string]byte, error) {
	updatedDomainHash := make(map[string]byte)
	// read from previous map
	// the map records: domain - certs pair
	// Which domain will be affected by which certificates
	for domainName, certs := range certDomainMap {
		for _, cert := range certs {
			domainNameHash := hex.EncodeToString(trie.Hasher([]byte(domainName)))
			// get domian entries
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
				newDomainEntry := &common.DomainEntry{DomainName: domainName}
				domainEntries[domainNameHash] = newDomainEntry
				isUpdated := updateDomainEntry(newDomainEntry, cert)
				if isUpdated {
					// flag the updated domains
					updatedDomainHash[domainNameHash] = 1
				}
			}
		}
	}
	return updatedDomainHash, nil
}

// insert certificate into correct CAEntry
func updateDomainEntry(domainEntry *common.DomainEntry, cert *x509.Certificate) bool {
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
		domainEntry.CAEntry = append(domainEntry.CAEntry, common.CAEntry{
			DomainCerts: [][]byte{cert.Raw},
			CAName:      caName,
			CAHash:      trie.Hasher([]byte(caName))})
		isUpdated = true
	}
	return isUpdated
}

// get updated domains, and extract the cooresponding domain bytes
func getDomainEntriesToWrite(updatedDomain map[string]byte, domainEntries map[string]*common.DomainEntry) (map[string]*common.DomainEntry, error) {
	result := make(map[string]*common.DomainEntry)
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

// sort domain entries
func sortDomainEntry(domainEntry *common.DomainEntry) {
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

// serialise the updated domains
func serialiseUpdatedDomainEntries(input map[string]*common.DomainEntry) ([]db.KeyValuePair, []string, error) {
	result := []db.KeyValuePair{}
	updatedDomainName := []string{}
	for k, v := range input {
		domainBytes, err := common.SerialiseDomainEnrty(v)
		if err != nil {
			return nil, nil, fmt.Errorf("serialiseUpdatedDomainEntries | SerialiseDomainEnrty | %w", err)
		}
		result = append(result, db.KeyValuePair{Key: k, Value: domainBytes})
		updatedDomainName = append(updatedDomainName, k)
	}
	return result, updatedDomainName, nil
}
