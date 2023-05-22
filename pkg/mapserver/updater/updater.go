package updater

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"time"

	_ "github.com/go-sql-driver/mysql"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/db/mysql"
	"github.com/netsec-ethz/fpki/pkg/mapserver/logpicker"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
	"github.com/netsec-ethz/fpki/pkg/util"
)

// MapUpdater: map updater. It is responsible for updating the tree, and writing to db
type MapUpdater struct {
	Fetcher logpicker.LogFetcher
	smt     *trie.Trie
	dbConn  db.Conn
}

// NewMapUpdater: return a new map updater.
func NewMapUpdater(config *db.Configuration, root []byte, cacheHeight int) (*MapUpdater, error) {
	// db conn for map updater
	dbConn, err := mysql.Connect(config)
	if err != nil {
		return nil, fmt.Errorf("NewMapUpdater | db.Connect | %w", err)
	}

	// SMT
	smt, err := trie.NewTrie(root, common.SHA256Hash, dbConn)
	if err != nil {
		return nil, fmt.Errorf("NewMapServer | NewTrie | %w", err)
	}
	smt.CacheHeightLimit = cacheHeight

	return &MapUpdater{
		Fetcher: logpicker.LogFetcher{
			WorkerCount: 16,
		},
		smt:    smt,
		dbConn: dbConn,
	}, nil
}

// StartFetching will initiate the CT logs fetching process in the background, trying to
// obtain the next batch of certificates and have it ready for the next update.
func (u *MapUpdater) StartFetching(ctURL string, startIndex, endIndex int) {
	u.Fetcher.URL = ctURL
	u.Fetcher.Start = startIndex
	u.Fetcher.End = endIndex
	u.Fetcher.StartFetching()
}

// UpdateNextBatch downloads the next batch from the CT log server and updates the domain and
// Updates tables. Also the SMT.
func (u *MapUpdater) UpdateNextBatch(ctx context.Context) (int, error) {
	certs, err := u.Fetcher.NextBatch(ctx)
	if err != nil {
		return 0, fmt.Errorf("CollectCerts | GetCertMultiThread | %w", err)
	}
	// TODO(cyrill): parse and add certificate chains from CT log server
	emptyCertChains := make([][]*ctx509.Certificate, len(certs))
	return len(certs), u.updateCerts(ctx, certs, emptyCertChains)
}

// UpdateCertsLocally: add certs (in the form of asn.1 encoded byte arrays) directly without querying log
func (mapUpdater *MapUpdater) UpdateCertsLocally(ctx context.Context, certList [][]byte, certChainList [][][]byte) error {
	expirations := make([]*time.Time, 0, len(certList))
	certs := make([]*ctx509.Certificate, 0, len(certList))
	certChains := make([][]*ctx509.Certificate, 0, len(certList))
	for i, certRaw := range certList {
		cert, err := ctx509.ParseCertificate(certRaw)
		if err != nil {
			return err
		}
		certs = append(certs, cert)
		expirations = append(expirations, &cert.NotAfter)

		chain := make([]*ctx509.Certificate, len(certChainList[i]))
		for i, certChainItemRaw := range certChainList[i] {
			chain[i], err = ctx509.ParseCertificate(certChainItemRaw)
			if err != nil {
				return err
			}
		}
		certChains = append(certChains, chain)
	}
	certs, IDs, parentIDs, names := util.UnfoldCerts(certs, certChains)
	return UpdateWithKeepExisting(ctx, mapUpdater.dbConn, names, IDs, parentIDs, certs, expirations, nil)
}

// updateCerts: update the tables and SMT (in memory) using certificates
func (mapUpdater *MapUpdater) updateCerts(ctx context.Context, certs []*ctx509.Certificate, certChains [][]*ctx509.Certificate) error {
	panic("deprecated: should never be called")
	keyValuePairs, numOfUpdates, err := mapUpdater.DeletemeUpdateDomainEntriesTableUsingCerts(ctx, certs, certChains)
	if err != nil {
		return fmt.Errorf("CollectCerts | UpdateDomainEntriesUsingCerts | %w", err)
	} else if numOfUpdates == 0 {
		return nil
	}

	if len(keyValuePairs) == 0 {
		return nil
	}

	keyInput, valueInput, err := keyValuePairToSMTInput(keyValuePairs)
	if err != nil {
		return fmt.Errorf("CollectCerts | keyValuePairToSMTInput | %w", err)
	}

	_, err = mapUpdater.smt.Update(ctx, keyInput, valueInput)
	if err != nil {
		return fmt.Errorf("CollectCerts | Update | %w", err)
	}

	return nil
}

// UpdateRPCAndPC: update RPC and PC from url. Currently just mock PC and RPC
func (mapUpdater *MapUpdater) UpdateRPCAndPC(ctx context.Context, ctUrl string, startIdx, endIdx int64) error {
	// get PC and RPC first
	pcList, rpcList, err := logpicker.GetPCAndRPC(ctUrl, startIdx, endIdx, 20)
	if err != nil {
		return fmt.Errorf("CollectCerts | GetPCAndRPC | %w", err)
	}
	return mapUpdater.updateRPCAndPC(ctx, pcList, rpcList)
}

// UpdateRPCAndPCLocally: update RPC and PC, given a rpc and sp. Currently just mock PC and RPC
func (mapUpdater *MapUpdater) UpdateRPCAndPCLocally(ctx context.Context, spList []*common.SP, rpcList []*common.RPC) error {
	return mapUpdater.updateRPCAndPC(ctx, spList, rpcList)
}

// updateRPCAndPC: update the tables and SMT (in memory) using PC and RPC
func (mapUpdater *MapUpdater) updateRPCAndPC(ctx context.Context, pcList []*common.SP, rpcList []*common.RPC) error {
	// update the domain and
	keyValuePairs, _, err := mapUpdater.DeletemeUpdateDomainEntriesTableUsingRPCAndPC(ctx, rpcList, pcList, 10)
	if err != nil {
		return fmt.Errorf("CollectCerts | UpdateDomainEntriesUsingRPCAndPC | %w", err)
	}

	if len(keyValuePairs) == 0 {
		return nil
	}

	keyInput, valueInput, err := keyValuePairToSMTInput(keyValuePairs)
	if err != nil {
		return fmt.Errorf("CollectCerts | keyValuePairToSMTInput | %w", err)
	}

	// update Sparse Merkle Tree
	_, err = mapUpdater.smt.Update(ctx, keyInput, valueInput)
	if err != nil {
		return fmt.Errorf("CollectCerts | Update | %w", err)
	}
	return nil
}

// CommitSMTChanges: commit SMT changes to DB
func (mapUpdater *MapUpdater) CommitSMTChanges(ctx context.Context) error {
	err := mapUpdater.smt.Commit(ctx)
	if err != nil {
		return fmt.Errorf("CommitChanges | Commit | %w", err)
	}
	return nil
}

// fetchUpdatedDomainHash: get hashes of updated domain from updates table, and truncate the table
func (mapUpdater *MapUpdater) fetchUpdatedDomainHash(ctx context.Context) ([]common.SHA256Output, error) {
	keys, err := mapUpdater.dbConn.RetrieveUpdatedDomains(ctx, readBatchSize)
	if err != nil {
		return nil, fmt.Errorf("fetchUpdatedDomainHash | %w", err)
	}

	err = mapUpdater.dbConn.RemoveAllUpdatedDomains(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetchUpdatedDomainHash | %w", err)
	}

	return keys, nil
}

// keyValuePairToSMTInput: key value pair -> SMT update input
// deleteme: this function takes the payload and computes the hash of it. The hash is already
// stored in the DB with the new design: change both the function RetrieveDomainEntries and
// remove the hashing from this keyValuePairToSMTInput function.
func keyValuePairToSMTInput(keyValuePair []*db.KeyValuePair) ([][]byte, [][]byte, error) {
	type inputPair struct {
		Key   [32]byte
		Value []byte
	}
	updateInput := make([]inputPair, 0, len(keyValuePair))
	for _, pair := range keyValuePair {
		updateInput = append(updateInput, inputPair{
			Key:   pair.Key,
			Value: common.SHA256Hash(pair.Value), // Compute SHA256 of the payload.
		})
	}

	// Sorting is important, as the Trie.Update function expects the keys in sorted order.
	sort.Slice(updateInput, func(i, j int) bool {
		return bytes.Compare(updateInput[i].Key[:], updateInput[j].Key[:]) == -1
	})

	keyResult := make([][]byte, 0, len(updateInput))
	valueResult := make([][]byte, 0, len(updateInput))

	for _, pair := range updateInput {
		// TODO(yongzhe): strange error
		// if I do : append(keyResult, pair.Key[:]), the other elements in the slice will be affected
		// Looks like the slice is storing the pointer of the value.
		// However, append(valueResult, pair.Value) also works. I will have a look later
		var newKey [32]byte
		copy(newKey[:], pair.Key[:])
		keyResult = append(keyResult, newKey[:])

		valueResult = append(valueResult, pair.Value)

	}

	return keyResult, valueResult, nil
}

// GetRoot: get current root
func (mapUpdater *MapUpdater) GetRoot() []byte {
	return mapUpdater.smt.Root
}

// Close: close connection
func (mapUpdater *MapUpdater) Close() error {
	return mapUpdater.smt.Close()
}

func UpdateWithOverwrite(ctx context.Context, conn db.Conn, domainNames [][]string,
	certIDs, parentCertIDs []*common.SHA256Output,
	certs []*ctx509.Certificate, certExpirations []*time.Time,
	policies []common.PolicyObject,
) error {

	// Insert all specified certificates.
	payloads := make([][]byte, len(certs))
	for i, c := range certs {
		payloads[i] = c.Raw

	}
	err := insertCerts(ctx, conn, domainNames, certIDs, parentCertIDs, certExpirations, payloads)
	if err != nil {
		return err
	}

	// Insert all specified policies.
	payloads = make([][]byte, len(policies))
	policyIDs := make([]*common.SHA256Output, len(policies))
	policySubjects := make([]string, len(policies))
	for i, pol := range policies {
		payloads[i] = pol.Raw()
		id := common.SHA256Hash32Bytes(pol.Raw())
		policyIDs[i] = &id
		policySubjects[i] = pol.Domain()
	}
	err = insertPolicies(ctx, conn, policySubjects, policyIDs, payloads)

	return err
}

func UpdateWithKeepExisting(ctx context.Context, conn db.Conn, domainNames [][]string,
	certIDs, parentCertIDs []*common.SHA256Output,
	certs []*ctx509.Certificate, certExpirations []*time.Time,
	policies []common.PolicyObject,
) error {

	// First check which certificates are already present in the DB.
	maskCerts, err := conn.CheckCertsExist(ctx, certIDs)
	if err != nil {
		return err
	}

	// For all those certificates not already present in the DB, prepare three slices: IDs,
	// names, payloads, and parentIDs.
	payloads := make([][]byte, 0, len(certs))
	runWhenFalse(maskCerts, func(to, from int) {
		certIDs[to] = certIDs[from]
		domainNames[to] = domainNames[from]
		parentCertIDs[to] = parentCertIDs[from]
		payloads = append(payloads, certs[from].Raw)
	})
	// Trim the end of the original ID slice, as it contains values from the unmasked certificates.
	certIDs = certIDs[:len(payloads)]
	domainNames = domainNames[:len(payloads)]
	parentCertIDs = parentCertIDs[:len(payloads)]

	// Update those certificates that were not in the mask.
	err = insertCerts(ctx, conn, domainNames, certIDs, parentCertIDs, certExpirations, payloads)
	if err != nil {
		return err
	}

	// Prepare data structures for the policies.
	payloads = make([][]byte, len(policies))
	policyIDs := make([]*common.SHA256Output, len(policies))
	policySubjects := make([]string, len(policies))
	for i, pol := range policies {
		payloads[i] = pol.Raw()
		id := common.SHA256Hash32Bytes(pol.Raw())
		policyIDs[i] = &id
		policySubjects[i] = pol.Domain()
	}
	// Check which policies are already present in the DB.
	maskPols, err := conn.CheckPoliciesExist(ctx, policyIDs)
	if err != nil {
		return err
	}
	n := runWhenFalse(maskPols, func(to, from int) {
		policyIDs[to] = policyIDs[from]
		payloads[to] = payloads[from]
		policySubjects[to] = policySubjects[from]
	})
	policyIDs = policyIDs[:n]
	payloads = payloads[:n]
	policySubjects = policySubjects[:n]
	// Update those policies that were not in the mask.
	err = insertPolicies(ctx, conn, policySubjects, policyIDs, payloads)

	return err
}

func CoalescePayloadsForDirtyDomains(ctx context.Context, conn db.Conn) error {
	// How many domains to update?
	dirtyCount, err := conn.DirtyDomainsCount(ctx)
	if err != nil {
		return err
	}
	// Do all updates at once, in one thread/connection (faster than multiple routines).
	if err := conn.ReplaceDirtyDomainPayloads(ctx, 0, dirtyCount-1); err != nil {
		return fmt.Errorf("coalescing payloads of dirty domains: %w", err)
	}
	return nil
}

func UpdateSMTfromDomains(
	ctx context.Context,
	conn db.Conn,
	smtTrie *trie.Trie,
	domainIDs []*common.SHA256Output,
) error {

	// Read those certificates:
	entries, err := conn.RetrieveDomainEntries(ctx, domainIDs)
	if err != nil {
		return err
	}
	keys, values, err := keyValuePairToSMTInput(entries)
	if err != nil {
		return err
	}

	// Update the tree.
	_, err = smtTrie.Update(ctx, keys, values)
	if err != nil {
		return err
	}
	// And update the tree in the DB.
	err = smtTrie.Commit(ctx)
	if err != nil {
		return err
	}
	return nil
}

// UpdateSMT reads all the dirty domains (pending to update their contents in the SMT), creates
// a SMT Trie, loads it, and updates its entries with the new values.
// It finally commits the Trie and saves its root in the DB.
func UpdateSMT(ctx context.Context, conn db.Conn, cacheHeight int) error {
	// Load root.
	var root []byte
	if rootID, err := conn.LoadRoot(ctx); err != nil {
		return err
	} else if rootID != nil {
		root = rootID[:]
	}

	// Load SMT.
	smtTrie, err := trie.NewTrie(root, common.SHA256Hash, conn)
	if err != nil {
		panic(err)
	}
	// smtTrie.CacheHeightLimit = cacheHeight

	// Get the dirty domains.
	domains, err := conn.UpdatedDomains(ctx)
	if err != nil {
		return err
	}
	err = UpdateSMTfromDomains(ctx, conn, smtTrie, domains)
	if err != nil {
		return err
	}

	// Save root value:
	err = conn.SaveRoot(ctx, (*common.SHA256Output)(smtTrie.Root))
	if err != nil {
		return err
	}

	return nil
}

func insertCerts(ctx context.Context, conn db.Conn, names [][]string,
	ids, parentIDs []*common.SHA256Output, expirations []*time.Time, payloads [][]byte) error {

	// Send hash, parent hash, expiration and payload to the certs table.
	if err := conn.InsertCerts(ctx, ids, parentIDs, expirations, payloads); err != nil {
		return fmt.Errorf("inserting certificates: %w", err)
	}

	// Add new entries from names into the domains table iff they are leaves.
	estimatedSize := len(ids) * 2 // Number of IDs / 3 ~~ is the number of leaves. 6 names per leaf.
	newNames := make([]string, 0, estimatedSize)
	newIDs := make([]*common.SHA256Output, 0, estimatedSize)
	domainIDs := make([]*common.SHA256Output, 0, estimatedSize)
	for i, names := range names {
		// Iff the certificate is a leaf certificate it will have a non-nil names slice: insert
		// one entry per name.
		for _, name := range names {
			newNames = append(newNames, name)
			newIDs = append(newIDs, ids[i])
			domainID := common.SHA256Hash32Bytes([]byte(name))
			domainIDs = append(domainIDs, &domainID)
		}
	}
	// Push the changes of the domains to the DB.
	if err := conn.UpdateDomains(ctx, domainIDs, newNames); err != nil {
		return fmt.Errorf("updating domains: %w", err)
	}
	if err := conn.UpdateDomainCerts(ctx, domainIDs, newIDs); err != nil {
		return fmt.Errorf("updating domain_certs: %w", err)
	}

	return nil
}

func insertPolicies(ctx context.Context, conn db.Conn, names []string, ids []*common.SHA256Output,
	payloads [][]byte) error {

	// TODO(juagargi) use parent IDs for the policies

	// Push the changes of the domains to the DB.
	domainIDs := make([]*common.SHA256Output, len(names))
	for i, name := range names {
		domainID := common.SHA256Hash32Bytes([]byte(name))
		domainIDs[i] = &domainID
	}
	if err := conn.UpdateDomains(ctx, domainIDs, names); err != nil {
		return fmt.Errorf("updating domains: %w", err)
	}

	// Update the policies in the DB, with nil parents and mock expirations.
	// Sequence of nil parent ids:
	parents := make([]*common.SHA256Output, len(ids))
	// Sequence of expiration times way in the future:
	expirations := make([]*time.Time, len(ids))
	for i := range expirations {
		t := time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC) // TODO(juagargi) use real expirations.
		expirations[i] = &t
	}
	// Update policies:
	if err := conn.InsertPolicies(ctx, ids, parents, expirations, payloads); err != nil {
		return fmt.Errorf("inserting policies: %w", err)
	}

	if err := conn.UpdateDomainPolicies(ctx, domainIDs, ids); err != nil {
		return fmt.Errorf("updating domain_certs: %w", err)
	}

	return nil
}

// runWhenFalse serves as a function to "move" content when the element in mask is true.
// Returns the number of false entries.
func runWhenFalse(mask []bool, fcn func(to, from int)) int {
	to := 0
	for from, condition := range mask {
		if !condition {
			fcn(to, from)
			to++
		}
	}
	return to
}
