package updater

import (
	"context"
	"fmt"
	"time"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/domain"
	mcommon "github.com/netsec-ethz/fpki/pkg/mapserver/common"
)

// TODO(yongzhe): make the list if size is already known.
// TODO(yongzhe): unit test for updateDomainEntryWithRPC and

type uniqueSet map[common.SHA256Output]struct{}
type uniqueStringSet map[string]struct{}

// UpdateDomainEntriesTableUsingCerts: Update the domain entries using the domain certificates
func (mapUpdater *MapUpdater) UpdateDomainEntriesTableUsingCerts(
	ctx context.Context,
	certs []*ctx509.Certificate,
	certChains [][]*ctx509.Certificate,
) (
	[]*db.KeyValuePair,
	int,
	error,
) {

	if len(certs) == 0 {
		return nil, 0, nil
	}

	start := time.Now()
	// get the unique list of affected domains
	affectedDomainsSet, domainCertMap, domainCertChainMap := GetAffectedDomainAndCertMap(
		certs, certChains)
	end := time.Now()
	fmt.Println("(memory) time to process certs: ", end.Sub(start))

	// if no domain to update
	if len(affectedDomainsSet) == 0 {
		return nil, 0, nil
	}

	start = time.Now()
	// retrieve (possibly)affected domain entries from db
	// It's possible that no records will be changed, because the certs are already recorded.
	domainEntriesMap, err := mapUpdater.retrieveAffectedDomainFromDB(ctx, affectedDomainsSet)
	if err != nil {
		return nil, 0, fmt.Errorf("UpdateDomainEntriesTableUsingCerts | %w", err)
	}
	end = time.Now()
	fmt.Println("(db)     time to retrieve domain entries: ", end.Sub(start))

	start = time.Now()
	// update the domain entries
	updatedDomains, err := UpdateDomainEntries(domainEntriesMap, domainCertMap, domainCertChainMap)
	if err != nil {
		return nil, 0, fmt.Errorf("UpdateDomainEntriesTableUsingCerts | updateDomainEntries | %w", err)
	}
	end = time.Now()
	fmt.Println("(db)     time to update domain entries: ", end.Sub(start))

	// if during this updates, no cert is added, directly return
	if len(updatedDomains) == 0 {
		return nil, 0, nil
	}

	start = time.Now()
	// get the domain entries only if they are updated, from DB
	domainEntriesToWrite, err := GetDomainEntriesToWrite(updatedDomains, domainEntriesMap)
	if err != nil {
		return nil, 0, fmt.Errorf("UpdateDomainEntriesTableUsingCerts | getDomainEntriesToWrite | %w", err)
	}

	// serialized the domainEntry -> key-value pair
	keyValuePairs, err := SerializeUpdatedDomainEntries(domainEntriesToWrite)
	if err != nil {
		return nil, 0, fmt.Errorf("UpdateDomainEntriesTableUsingCerts | serializeUpdatedDomainEntries | %w", err)
	}
	end = time.Now()
	fmt.Println("(memory) time to process updated domains: ", end.Sub(start))

	start = time.Now()
	// commit changes to db
	num, err := mapUpdater.writeChangesToDB(ctx, keyValuePairs)
	if err != nil {
		return nil, 0, fmt.Errorf("UpdateDomainEntriesTableUsingCerts | writeChangesToDB | %w", err)
	}
	end = time.Now()
	fmt.Println("(db)     time to write updated domain entries: ", end.Sub(start))

	return keyValuePairs, num, nil
}

// return affected domains.
// First return value: map of hashes of updated domain name. TODO(yongzhe): change this to a list maybe
// Second return value: "domain name" -> certs. So later, one can look through the map to decide which certs to
//
//	added to which domain.
func GetAffectedDomainAndCertMap(certs []*ctx509.Certificate, certChains [][]*ctx509.Certificate) (uniqueSet,
	map[string][]*ctx509.Certificate, map[string][][]*ctx509.Certificate) {
	// Set with the SHAs of the updated domains.
	affectedDomainsMap := make(uniqueSet)

	// Map "domain name" -> cert list (certs to be added to this domain).
	domainCertMap := make(map[string][]*ctx509.Certificate)

	// Analogous to the map above except that we map "domain name" -> cert chains.
	domainCertChainMap := make(map[string][][]*ctx509.Certificate)

	// extract the affected domain of every certificates
	for i, cert := range certs {
		// get cert chain for cert
		certChain := certChains[i]

		// get unique list of domain names
		domains := ExtractCertDomains(cert)
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
				domainCertChainMap[domainName] = append(domainCertChainMap[domainName], certChain)
			} else {
				domainCertMap[domainName] = []*ctx509.Certificate{cert}
				domainCertChainMap[domainName] = [][]*ctx509.Certificate{certChain}
			}
		}
	}
	return affectedDomainsMap, domainCertMap, domainCertChainMap
}

// UnfoldCerts takes a slice of certificates and chains with the same length,
// and returns all certificates once, without duplicates, and the ID of the parent in the
// trust chain, or nil if the certificate is root.
// The parents returned slice has the same elements as the certificates returned slice.
// When a certificate is root, it's corresponding parents entry is nil.
// Additionally, all the names of the leaf certificates are returned in its corresponding position
// in the names slice iff the certificate is a leaf one. If it is not, nil is returned in that
// position instead.
//
// The leaf certificates are always returned at the head of the slice, which means, among others,
// that once a nil value is found in the names slice, the rest of the slice will be nil as well.
func UnfoldCerts(leafCerts []*ctx509.Certificate, chains [][]*ctx509.Certificate,
) (
	certificates []*ctx509.Certificate,
	certIDs []*common.SHA256Output,
	parentIDs []*common.SHA256Output,
	names [][]string,
) {

	// extractNames is the function that extracts the names from a certificate. It starts being
	// a regular names extraction, but after processing all leaves it is assigned to a function
	// that always returns nil.
	extractNames := func(c *ctx509.Certificate) []string {
		return ExtractCertDomains(c)
	}
	// ChangeFcn changes extractNames to always return nil.
	changeFcn := func() {
		extractNames = func(c *ctx509.Certificate) []string {
			return nil
		}
	}

	for len(leafCerts) > 0 {
		var pendingCerts []*ctx509.Certificate
		var pendingChains [][]*ctx509.Certificate
		for i, c := range leafCerts {
			certificates = append(certificates, c)
			ID := common.SHA256Hash32Bytes(c.Raw)
			certIDs = append(certIDs, &ID)
			var parentID *common.SHA256Output
			if len(chains[i]) > 0 {
				// The certificate has a trust chain (it is not root): add the first certificate
				// from the chain as the parent.
				parent := chains[i][0]
				ID := common.SHA256Hash32Bytes(parent.Raw)
				parentID = &ID
				// Add this parent to the back of the certs, plus the corresponding chain entry,
				// so that it's processed as a certificate.
				pendingCerts = append(pendingCerts, parent)
				pendingChains = append(pendingChains, chains[i][1:])
			}
			parentIDs = append(parentIDs, parentID)
			names = append(names, extractNames(c))
		}
		changeFcn() // This will change the function `extractNames` to always return nil.
		leafCerts = pendingCerts
		chains = pendingChains
	}
	return
}

// UnfoldCert takes a certificate with its trust chain and returns a ready-to-insert-in-DB
// collection of IDs and payloads for the certificate and its ancestry.
// Additionally, if the payload of any of the ancestors of the certificate is nil, this function
// interprets it as the ancestor is already present in the DB, and thus will omit returning it
// and any posterior ancestors.
func UnfoldCert(leafCert *ctx509.Certificate, certID *common.SHA256Output,
	chain []*ctx509.Certificate, chainIDs []*common.SHA256Output,
) (
	certs []*ctx509.Certificate,
	certIDs []*common.SHA256Output,
	parentIDs []*common.SHA256Output,
	names [][]string,
) {

	certs = make([]*ctx509.Certificate, 0, len(chainIDs)+1)
	certIDs = make([]*common.SHA256Output, 0, len(chainIDs)+1)
	parentIDs = make([]*common.SHA256Output, 0, len(chainIDs)+1)
	names = make([][]string, 0, len(chainIDs)+1)

	// Always add the leaf certificate.
	certs = append(certs, leafCert)
	certIDs = append(certIDs, certID)
	parentIDs = append(parentIDs, chainIDs[0])
	names = append(names, ExtractCertDomains(leafCert))
	// Add the intermediate certs iff their payload is not nil.
	i := 0
	for ; i < len(chain)-1; i++ {
		if chain[i] == nil {
			// This parent has been inserted already in DB. This implies that its own parent,
			// the grandparent of the leaf, must have been inserted as well; and so on.
			// There are no more parents to insert.
			return
		}
		certs = append(certs, chain[i])
		certIDs = append(certIDs, chainIDs[i])
		parentIDs = append(parentIDs, chainIDs[i+1])
		names = append(names, nil)
	}
	// Add the root certificate (no parent) iff we haven't inserted it yet.
	if chain[i] != nil {
		certs = append(certs, chain[i])
		certIDs = append(certIDs, chainIDs[i])
		parentIDs = append(parentIDs, nil)
		names = append(names, nil)
	}
	return
}

// update domain entries
func UpdateDomainEntries(domainEntries map[common.SHA256Output]*mcommon.DomainEntry,
	certDomainMap map[string][]*ctx509.Certificate, certChainDomainMap map[string][][]*ctx509.Certificate) (uniqueSet, error) {

	updatedDomainHash := make(uniqueSet)
	// read from previous map
	// the map records: domain - certs pair
	// Which domain will be affected by which certificates
	for domainName, certs := range certDomainMap {
		certChains := certChainDomainMap[domainName]
		//iterStart := time.Now()
		for i, cert := range certs {
			certChain := certChains[i]
			var domainNameHash common.SHA256Output
			copy(domainNameHash[:], common.SHA256Hash([]byte(domainName)))
			// get domain entries
			domainEntry, ok := domainEntries[domainNameHash]
			// if domain entry does not exist in the db
			if !ok {
				// create an empty domain entry
				newDomainEntry := &mcommon.DomainEntry{DomainName: domainName}
				domainEntries[domainNameHash] = newDomainEntry
				domainEntry = newDomainEntry
			}

			isUpdated := updateDomainEntry(domainEntry, cert, certChain)
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
func updateDomainEntry(domainEntry *mcommon.DomainEntry, cert *ctx509.Certificate, certChain []*ctx509.Certificate) bool {
	return domainEntry.AddCert(cert, certChain)
}

// GetDomainEntriesToWrite: get updated domains, and extract the domain bytes
func GetDomainEntriesToWrite(updatedDomain uniqueSet,
	domainEntries map[common.SHA256Output]*mcommon.DomainEntry) (map[common.SHA256Output]*mcommon.DomainEntry, error) {

	result := make(map[common.SHA256Output]*mcommon.DomainEntry)
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

// SerializeUpdatedDomainEntries: serialize the updated domains
func SerializeUpdatedDomainEntries(domains map[common.SHA256Output]*mcommon.DomainEntry) (
	[]*db.KeyValuePair, error) {

	result := make([]*db.KeyValuePair, 0, len(domains))

	for domainNameHash, domainEntryBytes := range domains {
		domainBytes, err := mcommon.SerializedDomainEntry(domainEntryBytes)
		if err != nil {
			return nil, fmt.Errorf("serializeUpdatedDomainEntries | SerializedDomainEntry | %w", err)
		}

		result = append(result, &db.KeyValuePair{Key: domainNameHash, Value: domainBytes})
	}
	return result, nil
}
