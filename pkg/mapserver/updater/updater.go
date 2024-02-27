package updater

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	_ "github.com/go-sql-driver/mysql"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/db/mysql"
	"github.com/netsec-ethz/fpki/pkg/mapserver/logfetcher"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
	"github.com/netsec-ethz/fpki/pkg/util"
)

// MapUpdater: map updater. It is responsible for downloading certificates from the multiple
// log servers, updating the tree, and writing to DB.
// When the MapUpdater is started, it will attempt to download certificartes from tne first
// URL in a batch.
type MapUpdater struct {
	Fetchers []logfetcher.Fetcher
	Conn     db.Conn

	currFetcher int              // the fetcher being used once StartFetchingRemaining is called
	lastState   logfetcher.State // last known server status
	currState   logfetcher.State // the current status
	// Don't use a Trie in memory. The updater just creates one when needed and disposes of it
	// afterwards.
}

// NewMapUpdater: return a new map updater.
func NewMapUpdater(config *db.Configuration, urls []string) (*MapUpdater, error) {
	if len(urls) == 0 {
		return nil, fmt.Errorf("No URLs")
	}
	// db conn for map updater
	dbConn, err := mysql.Connect(config)
	if err != nil {
		return nil, fmt.Errorf("NewMapUpdater | db.Connect | %w", err)
	}

	fetchers := make([]logfetcher.Fetcher, len(urls))
	alreadyURLs := make(map[string]struct{}, len(urls))
	for i, url := range urls {
		// Check if the url is already present.
		if _, ok := alreadyURLs[url]; ok {
			return nil, fmt.Errorf("URL %s is duplicated", url)
		}
		alreadyURLs[url] = struct{}{}
		// Keep a new fetcher for the url.
		fetchers[i], err = logfetcher.NewLogFetcher(url)
		if err != nil {
			return nil, err
		}
	}

	return &MapUpdater{
		Fetchers: fetchers,
		Conn:     dbConn,
	}, nil
}

func (u *MapUpdater) GetProgress() (string, int, int, error) {
	return u.Fetchers[u.currFetcher].URL(), int(u.lastState.Size), int(u.currState.Size), nil
}

// StartFetchingRemaining retrieves the last stored index number for this CT log server, and the
// current last index, and uses them to call StartFetching.
// It returns an error if there was one retrieving the start or end indices.
func (u *MapUpdater) StartFetchingRemaining() error {
	u.currFetcher = 0
	ctx, cancelF := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelF()

	return u.startNextFetcher(ctx)
}

func (u *MapUpdater) StopFetching() {
	if u.currFetcher < len(u.Fetchers) {
		// Stop the previous fetcher.
		u.Fetchers[u.currFetcher].StopFetching()
	}
}

func (u *MapUpdater) NextBatch(ctx context.Context) bool {
	return u.currFetcher < len(u.Fetchers) && u.Fetchers[u.currFetcher].NextBatch(ctx)
}

// UpdateNextBatch downloads the next batch from the CT log server and updates the domain and
// Updates tables. Also the SMT.
// TODO(juagargi) This can be optimized by having to pipelines: one for downloading and one for
// inserting into the DB. See also NextBatch.
func (u *MapUpdater) UpdateNextBatch(ctx context.Context) (int, error) {
	fetcher := u.Fetchers[u.currFetcher]
	certs, chains, err := fetcher.ReturnNextBatch()
	if err != nil {
		return 0, fmt.Errorf("fetcher: %w", err)
	}

	// Verify validity of this batch.
	// TODO(juagargi) It won't work like this. The only STHs we have are the last one and
	// the current one, and the batch end doesn't correspond to the current size (but only an
	// intermediate step).
	// We may want to start a transaction in the DB at the StartFetchingRemaining and commit it
	// only if the verification of all batches is alright.
	// Or we may want to insert batches and verify only the last one.
	// See issue #47
	// https://github.com/netsec-ethz/fpki/issues/47
	err = u.verifyValidity(ctx, certs, chains)
	if err != nil {
		return 0, fmt.Errorf("validity from CT log server: %w", err)
	}

	// Insert into DB.
	n, err := len(certs), u.updateCertBatch(ctx, certs, chains)
	if err != nil {
		return n, err
	}

	// Store the last status obtained from the fetcher as updated.
	u.lastState.Size += uint64(n)
	if u.lastState.Size == u.currState.Size {
		// Update the DB with all certs collected from this fetcher
		err = u.Conn.UpdateLastCTlogServerState(ctx, fetcher.URL(),
			int64(u.currState.Size),
			u.currState.STH)
		// Prepare the next fetcher:
		u.currFetcher++
		u.startNextFetcher(ctx)
	}

	return n, err
}

// UpdateCertsLocally: add certs (in the form of asn.1 encoded byte arrays) directly
// without querying log.
func (u *MapUpdater) UpdateCertsLocally(
	ctx context.Context,
	certList [][]byte,
	certChainList [][][]byte,
) error {

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
	return UpdateWithKeepExisting(ctx, u.Conn, names, IDs, parentIDs, certs, expirations, nil)
}

// UpdatePolicyCerts: update RPC and PC from url. Currently just mock PC and RPC
func (u *MapUpdater) UpdatePolicyCerts(ctx context.Context, ctUrl string, startIdx, endIdx int64) error {
	// get PC and RPC first
	rpcList, err := logfetcher.GetPCAndRPCs(ctUrl, startIdx, endIdx, 20)
	if err != nil {
		return fmt.Errorf("CollectCerts | GetPCAndRPC | %w", err)
	}
	return u.updatePolicyCerts(ctx, rpcList)
}

func (u *MapUpdater) UpdateSMT(ctx context.Context) error {
	return UpdateSMT(ctx, u.Conn)
}

func (u *MapUpdater) CoalescePayloadsForDirtyDomains(ctx context.Context) error {
	return CoalescePayloadsForDirtyDomains(ctx, u.Conn)
}

func (u *MapUpdater) startNextFetcher(ctx context.Context) error {
	if u.currFetcher > 0 && u.currFetcher-1 < len(u.Fetchers) {
		// Stop the previous fetcher.
		u.Fetchers[u.currFetcher-1].StopFetching()
	}
	if u.currFetcher >= len(u.Fetchers) {
		return nil
	}

	fetcher := u.Fetchers[u.currFetcher]
	lastSize, lastSTH, err := u.Conn.LastCTlogServerState(ctx, fetcher.URL())
	if err != nil {
		return fmt.Errorf("getting the last retrieved index number from DB: %w", err)
	}
	// TODO(juagargi): use the fetcher's ctClient to get a new STH, and verify STH consistency
	// between the new and the old heads.

	u.lastState = logfetcher.State{
		Size: uint64(lastSize),
		STH:  lastSTH,
	}

	u.currState, err = fetcher.GetCurrentState(ctx)
	if err != nil {
		return fmt.Errorf("getting the size of the CT log server: %w", err)
	}

	fetcher.StartFetching(lastSize, int64(u.currState.Size)-1)
	return nil
}

func (u *MapUpdater) verifyValidity(
	ctx context.Context,
	leafCerts []*ctx509.Certificate,
	chains [][]*ctx509.Certificate,
) error {

	// TODO(juagargi): for each certificate in the batch, verify its proof of inclusion.
	// The new STH was consistent with the old one, so here it is enough to verify the inclusion
	// against the current head.
	// See certificate-transparency-go/client.GetRawEntries, .GetSTHConsistency, .GetProofByHash .
	// This function should probably accept data structures returned by the CT log server.
	// See certificate-transparency-go/client .
	return nil
}

func (u *MapUpdater) updateCertBatch(
	ctx context.Context,
	leafCerts []*ctx509.Certificate,
	chains [][]*ctx509.Certificate,
) error {

	if len(leafCerts) != len(chains) {
		return fmt.Errorf("inconsistent certs and chains count: %d and %d respectively",
			len(leafCerts), len(chains))
	}

	certs, certIDs, parentIDs, names := util.UnfoldCerts(leafCerts, chains)

	// Extract expirations.
	expirations := util.ExtractExpirations(certs)

	// Process whole batch.
	return UpdateWithKeepExisting(
		ctx,
		u.Conn,
		names,
		certIDs,
		parentIDs,
		certs,
		expirations,
		nil, // no policies in this call
	)
}

func (u *MapUpdater) updatePolicyCerts(
	ctx context.Context,
	rpcs []*common.PolicyCertificate,
) error {

	// TODO(juagargi)
	return nil
}

func UpdateWithOverwrite(ctx context.Context, conn db.Conn, domainNames [][]string,
	certIDs, parentCertIDs []*common.SHA256Output,
	certs []*ctx509.Certificate, certExpirations []*time.Time,
	policies []common.PolicyDocument,
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
		payload, err := common.ToJSON(pol)
		if err != nil {
			return err
		}
		payloads[i] = payload
		id := common.SHA256Hash32Bytes(payload)
		policyIDs[i] = &id
		policySubjects[i] = pol.Domain()
	}
	err = insertPolicies(ctx, conn, policySubjects, policyIDs, payloads)

	return err
}

func UpdateWithKeepExisting(ctx context.Context, conn db.Conn, domainNames [][]string,
	certIDs, parentCertIDs []*common.SHA256Output,
	certs []*ctx509.Certificate, certExpirations []*time.Time,
	policies []common.PolicyDocument,
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
		payload, err := pol.Raw()
		if err != nil {
			return err
		}
		payloads[i] = payload
		id := common.SHA256Hash32Bytes(payload)
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
	// Do all updates at once, in one thread/connection (faster than multiple routines).
	if err := conn.RecomputeDirtyDomainsCertAndPolicyIDs(ctx); err != nil {
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
func UpdateSMT(ctx context.Context, conn db.Conn) error {
	// Load root.
	root, err := loadRoot(ctx, conn)
	if err != nil {
		return err
	}
	// Load SMT.
	smtTrie, err := trie.NewTrie(root, common.SHA256Hash, conn)
	if err != nil {
		return fmt.Errorf("with root \"%s\", creating NewTrie: %w", hex.EncodeToString(root), err)
	}
	// smtTrie.CacheHeightLimit = 32

	// Get the dirty domains.
	domains, err := conn.RetrieveDirtyDomains(ctx)
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

func loadRoot(ctx context.Context, conn db.Conn) ([]byte, error) {
	var root []byte
	if rootID, err := conn.LoadRoot(ctx); err != nil {
		return nil, err
	} else if rootID != nil {
		root = rootID[:]
	}
	return root, nil
}

func insertCerts(ctx context.Context, conn db.Conn, names [][]string,
	ids, parentIDs []*common.SHA256Output, expirations []*time.Time, payloads [][]byte) error {

	// Send hash, parent hash, expiration and payload to the certs table.
	if err := conn.UpdateCerts(ctx, ids, parentIDs, expirations, payloads); err != nil {
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
	if err := conn.UpdatePolicies(ctx, ids, parents, expirations, payloads); err != nil {
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

// keyValuePairToSMTInput: key value pair -> SMT update input
// deleteme TODO this function takes the payload and computes the hash of it. The hash is already
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
