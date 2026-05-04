package updater

import (
	"context"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"math/rand"
	"path/filepath"
	"testing"
	"time"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/stretchr/testify/require"

	"github.com/netsec-ethz/fpki/pkg/common"
	dbpkg "github.com/netsec-ethz/fpki/pkg/db"
	mapcommon "github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/prover"
	"github.com/netsec-ethz/fpki/pkg/mapserver/responder"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
	"github.com/netsec-ethz/fpki/pkg/tests/random"
	"github.com/netsec-ethz/fpki/pkg/tests/testdb"
	"github.com/netsec-ethz/fpki/pkg/util"
)

type smtDomainKind int

const (
	smtCertOnly smtDomainKind = iota
	smtPolicyOnly
	smtCertsAndPolicies
)

type smtDomainSpec struct {
	name string
	kind smtDomainKind
	seed int64
}

type smtExpectedDomain struct {
	name      string
	certIDs   []common.SHA256Output
	policyIDs []common.SHA256Output
}

type smtProofCheck struct {
	domain  string
	present bool
}

type namedTest struct {
	*testing.T
	name string
}

func (t namedTest) Name() string {
	return t.name
}

func (e smtExpectedDomain) certBytes(t *testing.T) ([]byte, common.SHA256Output) {
	t.Helper()
	return glueSortedIDsAndComputeItsID(e.certIDs)
}

func (e smtExpectedDomain) policyBytes(t *testing.T) ([]byte, common.SHA256Output) {
	t.Helper()
	return glueSortedIDsAndComputeItsID(e.policyIDs)
}

// TestUpdateSMT_EmptyDirty_NoRootChange checks that UpdateSMT is a no-op when there are no dirty
// domains, both when the root is empty and when a previously computed root already exists.
func TestUpdateSMT_EmptyDirty_NoRootChange(t *testing.T) {
	t.Run("nil-root", func(t *testing.T) {
		ctx, conn := newSMTTestConn(t, "nil-root")

		err := UpdateSMT(ctx, conn)
		require.NoError(t, err)

		root := loadSavedRoot(t, ctx, conn)
		require.Nil(t, root)

		assertProofsValid(t, ctx, conn, smtProofCheck{domain: "absent.example.com", present: false})
	})

	t.Run("existing-root", func(t *testing.T) {
		ctx, conn := newSMTTestConn(t, "existing-root")
		populateScenario(t, ctx, conn, []smtDomainSpec{
			{name: "existing-root.example.com", kind: smtCertsAndPolicies, seed: 42},
		})
		require.NoError(t, CoalescePayloadsForDirtyDomains(ctx, conn))
		require.NoError(t, UpdateSMT(ctx, conn))
		original := loadSavedRoot(t, ctx, conn)
		require.NotNil(t, original)
		require.NoError(t, conn.CleanupDirty(ctx))

		err := UpdateSMT(ctx, conn)
		require.NoError(t, err)

		root := loadSavedRoot(t, ctx, conn)
		require.NotNil(t, root)
		require.Equal(t, *original, *root)

		assertProofsValid(t, ctx, conn,
			smtProofCheck{domain: "existing-root.example.com", present: true},
			smtProofCheck{domain: "absent.example.com", present: false},
		)
	})
}

// TestUpdateSMT_BundleSizeDoesNotAffectRoot checks that splitting the same dirty workload into
// different bundle sizes does not change the final SMT root or proof validity.
func TestUpdateSMT_BundleSizeDoesNotAffectRoot(t *testing.T) {
	specs := []smtDomainSpec{
		{name: "bundle-cert.example.com", kind: smtCertOnly, seed: 201},
		{name: "bundle-policy.example.com", kind: smtPolicyOnly, seed: 202},
		{name: "bundle-mixed.example.com", kind: smtCertsAndPolicies, seed: 203},
	}

	bundleSizes := []int{1, 2, len(specs) + 5}
	roots := make([]common.SHA256Output, 0, len(bundleSizes))
	for _, bundleSize := range bundleSizes {
		ctx, conn := newSMTTestConn(t, fmt.Sprintf("bundle-%d", bundleSize))
		populateScenario(t, ctx, conn, specs)
		require.NoError(t, CoalescePayloadsForDirtyDomains(ctx, conn))

		root := runDirtySMTPath(t, ctx, conn, bundleSize)
		roots = append(roots, root)

		assertProofsValid(t, ctx, conn,
			smtProofCheck{domain: "bundle-mixed.example.com", present: true},
			smtProofCheck{domain: "bundle-absent.example.com", present: false},
		)
	}

	for i := 1; i < len(roots); i++ {
		require.Equal(t, roots[0], roots[i])
	}
}

// TestUpdateSMTFromKeyValues_ResetsLiveCacheAfterEachCommit checks that each
// committed SMT bundle clears the trie live cache so memory does not accumulate
// across successive bundles.
func TestUpdateSMTFromKeyValues_ResetsLiveCacheAfterEachCommit(t *testing.T) {
	ctx, conn := newSMTTestConn(t, "cache-reset")
	populateScenario(t, ctx, conn, []smtDomainSpec{
		{name: "cache-a.example.com", kind: smtCertsAndPolicies, seed: 601},
		{name: "cache-b.example.com", kind: smtCertsAndPolicies, seed: 602},
	})
	require.NoError(t, CoalescePayloadsForDirtyDomains(ctx, conn))

	rootBytes, err := loadRoot(ctx, conn)
	require.NoError(t, err)

	smtTrie, err := trie.NewTrie(rootBytes, common.SHA256Hash, conn)
	require.NoError(t, err)
	smtTrie.CacheHeightLimit = 32

	var cursor *dbpkg.DirtyDomainEntriesCursor
	for i := 0; i < 2; i++ {
		entries, nextCursor, _, err := conn.RetrieveDomainEntriesDirtyBundle(ctx, cursor, 1)
		require.NoError(t, err)
		require.Len(t, entries, 1)

		require.NoError(t, updateSMTfromKeyValues(ctx, smtTrie, entries))
		require.Zero(t, smtTrie.GetLiveCacheSize())

		cursor = nextCursor
	}
}

// TestUpdateSMT_PersistsReloadableRoot checks that the root saved by UpdateSMT can be reloaded by
// a fresh responder instance and still serves valid proofs without any further updates.
func TestUpdateSMT_PersistsReloadableRoot(t *testing.T) {
	ctx, conn := newSMTTestConn(t, "persist")
	expected := populateScenario(t, ctx, conn, []smtDomainSpec{
		{name: "persist-cert.example.com", kind: smtCertOnly, seed: 301},
		{name: "persist-policy.example.com", kind: smtPolicyOnly, seed: 302},
		{name: "persist-mixed.example.com", kind: smtCertsAndPolicies, seed: 303},
	})

	require.NoError(t, CoalescePayloadsForDirtyDomains(ctx, conn))
	require.NoError(t, UpdateSMT(ctx, conn))

	savedRoot := loadSavedRoot(t, ctx, conn)
	require.NotNil(t, savedRoot)

	loadedRoot, err := conn.LoadRoot(ctx)
	require.NoError(t, err)
	require.NotNil(t, loadedRoot)
	require.Equal(t, *savedRoot, *loadedRoot)

	assertProofsValid(t, ctx, conn,
		smtProofCheck{domain: "persist-cert.example.com", present: true},
		smtProofCheck{domain: "persist-policy.example.com", present: true},
		smtProofCheck{domain: "persist-absent.example.com", present: false},
	)
	assertLeafEntryMatches(t, ctx, conn, expected["persist-cert.example.com"])
	assertLeafEntryMatches(t, ctx, conn, expected["persist-policy.example.com"])
}

// TestUpdateSMT_IncrementalUpdateMatchesFreshBuild checks that applying a second wave of changes
// incrementally yields the same final root and proofs as rebuilding from the final state directly.
func TestUpdateSMT_IncrementalUpdateMatchesFreshBuild(t *testing.T) {
	initialSpecs := []smtDomainSpec{
		{name: "unchanged.example.com", kind: smtCertOnly, seed: 401},
		{name: "modified.example.com", kind: smtPolicyOnly, seed: 402},
		{name: "other.example.com", kind: smtCertsAndPolicies, seed: 403},
	}
	finalSpecs := []smtDomainSpec{
		{name: "unchanged.example.com", kind: smtCertOnly, seed: 401},
		{name: "modified.example.com", kind: smtCertsAndPolicies, seed: 502},
		{name: "other.example.com", kind: smtCertsAndPolicies, seed: 403},
		{name: "new.example.com", kind: smtPolicyOnly, seed: 404},
	}

	ctxInc, connInc := newSMTTestConn(t, "incremental")
	populateScenario(t, ctxInc, connInc, initialSpecs)
	require.NoError(t, CoalescePayloadsForDirtyDomains(ctxInc, connInc))
	require.NoError(t, UpdateSMT(ctxInc, connInc))
	require.NoError(t, connInc.CleanupDirty(ctxInc))

	modifiedID := common.SHA256Hash32Bytes([]byte("modified.example.com"))
	_, err := connInc.DB().ExecContext(ctxInc, "DELETE FROM domain_certs WHERE domain_id = ?", modifiedID[:])
	require.NoError(t, err)
	_, err = connInc.DB().ExecContext(ctxInc, "DELETE FROM domain_policies WHERE domain_id = ?", modifiedID[:])
	require.NoError(t, err)
	require.NoError(t, connInc.InsertDomainsIntoDirty(ctxInc, []common.SHA256Output{modifiedID}))

	modifiedExpected := populateScenario(t, ctxInc, connInc, []smtDomainSpec{
		{name: "modified.example.com", kind: smtCertsAndPolicies, seed: 502},
		{name: "new.example.com", kind: smtPolicyOnly, seed: 404},
	})
	require.NoError(t, CoalescePayloadsForDirtyDomains(ctxInc, connInc))
	require.NoError(t, UpdateSMT(ctxInc, connInc))
	incrementalRoot := loadSavedRoot(t, ctxInc, connInc)
	require.NotNil(t, incrementalRoot)

	ctxFresh, connFresh := newSMTTestConn(t, "fresh")
	freshExpected := populateScenario(t, ctxFresh, connFresh, finalSpecs)
	require.NoError(t, CoalescePayloadsForDirtyDomains(ctxFresh, connFresh))
	require.NoError(t, UpdateSMT(ctxFresh, connFresh))
	freshRoot := loadSavedRoot(t, ctxFresh, connFresh)
	require.NotNil(t, freshRoot)

	require.Equal(t, *incrementalRoot, *freshRoot)
	assertProofsValid(t, ctxInc, connInc,
		smtProofCheck{domain: "modified.example.com", present: true},
		smtProofCheck{domain: "unchanged.example.com", present: true},
		smtProofCheck{domain: "new.example.com", present: true},
		smtProofCheck{domain: "absent.example.com", present: false},
	)
	assertProofsValid(t, ctxFresh, connFresh,
		smtProofCheck{domain: "modified.example.com", present: true},
		smtProofCheck{domain: "unchanged.example.com", present: true},
		smtProofCheck{domain: "new.example.com", present: true},
		smtProofCheck{domain: "absent.example.com", present: false},
	)
	assertLeafEntryMatches(t, ctxInc, connInc, modifiedExpected["modified.example.com"])
	assertLeafEntryMatches(t, ctxFresh, connFresh, freshExpected["modified.example.com"])
}

// TestUpdateSMT_RemovesStaleDomainFromTrie checks that a domain removed from the coalesced payloads
// is removed from the SMT as well and turns into a valid proof of absence.
func TestUpdateSMT_RemovesStaleDomainFromTrie(t *testing.T) {
	ctx, conn := newSMTTestConn(t, "stale")
	populateScenario(t, ctx, conn, []smtDomainSpec{
		{name: "stale.example.com", kind: smtCertsAndPolicies, seed: 601},
	})

	require.NoError(t, CoalescePayloadsForDirtyDomains(ctx, conn))
	require.NoError(t, UpdateSMT(ctx, conn))
	beforeRoot := loadSavedRoot(t, ctx, conn)
	require.NotNil(t, beforeRoot)
	assertProofsValid(t, ctx, conn, smtProofCheck{domain: "stale.example.com", present: true})

	require.NoError(t, conn.CleanupDirty(ctx))
	domainID := common.SHA256Hash32Bytes([]byte("stale.example.com"))
	_, err := conn.DB().ExecContext(ctx, "DELETE FROM domain_certs WHERE domain_id = ?", domainID[:])
	require.NoError(t, err)
	_, err = conn.DB().ExecContext(ctx, "DELETE FROM domain_policies WHERE domain_id = ?", domainID[:])
	require.NoError(t, err)
	require.NoError(t, conn.InsertDomainsIntoDirty(ctx, []common.SHA256Output{domainID}))

	require.NoError(t, CoalescePayloadsForDirtyDomains(ctx, conn))
	require.NoError(t, UpdateSMT(ctx, conn))
	afterRoot := loadSavedRoot(t, ctx, conn)
	require.NotNil(t, afterRoot)
	require.NotEqual(t, *beforeRoot, *afterRoot)

	assertProofsValid(t, ctx, conn, smtProofCheck{domain: "stale.example.com", present: false})
}

// TestUpdateSMT_MixedCertsPoliciesProofContents checks that proofs expose the expected cert-only,
// policy-only, and mixed payload contents after an SMT update.
func TestUpdateSMT_MixedCertsPoliciesProofContents(t *testing.T) {
	ctx, conn := newSMTTestConn(t, "proof-contents")
	expected := populateScenario(t, ctx, conn, []smtDomainSpec{
		{name: "proof-cert.example.com", kind: smtCertOnly, seed: 701},
		{name: "proof-policy.example.com", kind: smtPolicyOnly, seed: 702},
		{name: "proof-mixed.example.com", kind: smtCertsAndPolicies, seed: 703},
	})

	require.NoError(t, CoalescePayloadsForDirtyDomains(ctx, conn))
	require.NoError(t, UpdateSMT(ctx, conn))

	assertLeafEntryMatches(t, ctx, conn, expected["proof-cert.example.com"])
	assertLeafEntryMatches(t, ctx, conn, expected["proof-policy.example.com"])
	assertLeafEntryMatches(t, ctx, conn, expected["proof-mixed.example.com"])

	certLeaf := getLeafProof(t, ctx, conn, "proof-cert.example.com")
	require.Empty(t, certLeaf.DomainEntry.PolicyIDs)

	policyLeaf := getLeafProof(t, ctx, conn, "proof-policy.example.com")
	require.Empty(t, policyLeaf.DomainEntry.CertIDs)

	mixedLeaf := getLeafProof(t, ctx, conn, "proof-mixed.example.com")
	allIDs := append(common.BytesToIDs(mixedLeaf.DomainEntry.CertIDs),
		common.BytesToIDs(mixedLeaf.DomainEntry.PolicyIDs)...)
	require.NotEmpty(t, allIDs)
	require.Contains(t, allIDs, expected["proof-mixed.example.com"].certIDs[0])
}

// TestUpdateSMT_DirtyOrderingDoesNotAffectRoot checks that different insertion orders in the dirty
// table do not affect the final SMT root or the validity of representative proofs.
func TestUpdateSMT_DirtyOrderingDoesNotAffectRoot(t *testing.T) {
	specs := []smtDomainSpec{
		{name: "order-a.example.com", kind: smtCertOnly, seed: 801},
		{name: "order-b.example.com", kind: smtPolicyOnly, seed: 802},
		{name: "order-c.example.com", kind: smtCertsAndPolicies, seed: 803},
	}
	reversed := []common.SHA256Output{
		common.SHA256Hash32Bytes([]byte("order-c.example.com")),
		common.SHA256Hash32Bytes([]byte("order-b.example.com")),
		common.SHA256Hash32Bytes([]byte("order-a.example.com")),
	}
	shuffled := []common.SHA256Output{
		common.SHA256Hash32Bytes([]byte("order-b.example.com")),
		common.SHA256Hash32Bytes([]byte("order-c.example.com")),
		common.SHA256Hash32Bytes([]byte("order-a.example.com")),
	}

	ctxA, connA := newSMTTestConn(t, "order-reversed")
	populateScenario(t, ctxA, connA, specs)
	reorderDirtyDomains(t, ctxA, connA, reversed)
	require.NoError(t, CoalescePayloadsForDirtyDomains(ctxA, connA))
	rootA := runDirtySMTPath(t, ctxA, connA, len(specs)+2)

	ctxB, connB := newSMTTestConn(t, "order-shuffled")
	populateScenario(t, ctxB, connB, specs)
	reorderDirtyDomains(t, ctxB, connB, shuffled)
	require.NoError(t, CoalescePayloadsForDirtyDomains(ctxB, connB))
	rootB := runDirtySMTPath(t, ctxB, connB, len(specs)+2)

	require.Equal(t, rootA, rootB)
	require.Equal(t, rootA, *loadSavedRoot(t, ctxA, connA))
	require.Equal(t, rootB, *loadSavedRoot(t, ctxB, connB))

	assertProofsValid(t, ctxA, connA,
		smtProofCheck{domain: "order-a.example.com", present: true},
		smtProofCheck{domain: "order-absent.example.com", present: false},
	)
	assertProofsValid(t, ctxB, connB,
		smtProofCheck{domain: "order-a.example.com", present: true},
		smtProofCheck{domain: "order-absent.example.com", present: false},
	)
}

func newSMTTestConn(t *testing.T, suffix string) (context.Context, dbpkg.Conn) {
	t.Helper()

	sum := common.SHA256Hash32Bytes([]byte(t.Name() + "_" + suffix))
	tb := namedTest{T: t, name: "smt_" + hex.EncodeToString(sum[:8])}
	config, removeF := testdb.ConfigureTestDB(tb)
	t.Cleanup(removeF)

	conn := testdb.Connect(tb, config)
	t.Cleanup(func() {
		require.NoError(t, conn.Close())
	})

	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancelF)

	return ctx, conn
}

func populateScenario(
	t *testing.T,
	ctx context.Context,
	conn dbpkg.Conn,
	specs []smtDomainSpec,
) map[string]smtExpectedDomain {
	t.Helper()

	expected := make(map[string]smtExpectedDomain, len(specs))
	for _, spec := range specs {
		rand.Seed(spec.seed)

		var certIDs []common.SHA256Output
		var parentIDs []*common.SHA256Output
		var names [][]string
		var certs []ctx509.Certificate
		var policies []common.PolicyDocument

		if spec.kind != smtPolicyOnly {
			certs, certIDs, parentIDs, names = random.BuildTestRandomCertHierarchy(t, spec.name)
		}
		if spec.kind != smtCertOnly {
			policies = random.BuildTestRandomPolicyHierarchy(t, spec.name)
		}

		err := UpdateWithKeepExisting(
			ctx,
			conn,
			names,
			certIDs,
			parentIDs,
			certs,
			util.ExtractExpirations(certs),
			policies,
		)
		require.NoError(t, err)

		expected[spec.name] = smtExpectedDomain{
			name:      spec.name,
			certIDs:   append([]common.SHA256Output(nil), certIDs...),
			policyIDs: computeIDsOfPolicies(t, policies),
		}
	}

	return expected
}

func runDirtySMTPath(
	t *testing.T,
	ctx context.Context,
	conn dbpkg.Conn,
	bundleSize int,
) common.SHA256Output {
	t.Helper()

	rootBytes, err := loadRoot(ctx, conn)
	require.NoError(t, err)

	smtTrie, err := trie.NewTrie(rootBytes, common.SHA256Hash, conn)
	require.NoError(t, err)
	smtTrie.CacheHeightLimit = 32

	err = updateSMTfromDirty(ctx, conn, smtTrie, uint64(bundleSize))
	require.NoError(t, err)

	require.NotNil(t, smtTrie.Root)

	var root common.SHA256Output
	copy(root[:], smtTrie.Root)
	require.NoError(t, conn.SaveRoot(ctx, &root))
	return root
}

func loadSavedRoot(t *testing.T, ctx context.Context, conn dbpkg.Conn) *common.SHA256Output {
	t.Helper()
	root, err := conn.LoadRoot(ctx)
	require.NoError(t, err)
	return root
}

func reorderDirtyDomains(t *testing.T, ctx context.Context, conn dbpkg.Conn, ordered []common.SHA256Output) {
	t.Helper()
	require.NoError(t, conn.CleanupDirty(ctx))
	require.NoError(t, conn.InsertDomainsIntoDirty(ctx, ordered))
}

func assertProofsValid(
	t *testing.T,
	ctx context.Context,
	conn dbpkg.Conn,
	checks ...smtProofCheck,
) {
	t.Helper()
	for _, check := range checks {
		leaf := getLeafProof(t, ctx, conn, check.domain)
		if check.present {
			require.Equal(t, mapcommon.PoP, leaf.PoI.ProofType)
		} else {
			require.Equal(t, mapcommon.PoA, leaf.PoI.ProofType)
		}
	}
}

func getLeafProof(
	t *testing.T,
	ctx context.Context,
	conn dbpkg.Conn,
	domain string,
) *mapcommon.MapServerResponse {
	t.Helper()

	res, err := responder.NewMapResponder(ctx, conn, responderTestKey(t))
	require.NoError(t, err)

	proofs, err := res.GetProof(ctx, domain)
	require.NoError(t, err)
	require.NotEmpty(t, proofs)

	for _, proof := range proofs {
		_, ok, err := prover.VerifyProofByDomain(proof)
		require.NoError(t, err)
		require.True(t, ok)
	}

	return proofs[len(proofs)-1]
}

func assertLeafEntryMatches(
	t *testing.T,
	ctx context.Context,
	conn dbpkg.Conn,
	expected smtExpectedDomain,
) {
	t.Helper()

	leaf := getLeafProof(t, ctx, conn, expected.name)
	require.Equal(t, mapcommon.PoP, leaf.PoI.ProofType)

	wantCertBytes, wantCertID := expected.certBytes(t)
	wantPolicyBytes, wantPolicyID := expected.policyBytes(t)

	if len(expected.certIDs) == 0 {
		require.Empty(t, leaf.DomainEntry.CertIDs)
	} else {
		require.Equal(t, wantCertBytes, leaf.DomainEntry.CertIDs)
		require.Equal(t, wantCertID, leaf.DomainEntry.CertIDsID)
	}

	if len(expected.policyIDs) == 0 {
		require.Empty(t, leaf.DomainEntry.PolicyIDs)
	} else {
		require.Equal(t, wantPolicyBytes, leaf.DomainEntry.PolicyIDs)
		require.Equal(t, wantPolicyID, leaf.DomainEntry.PolicyIDsID)
	}
}

func responderTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	key, err := util.RSAKeyFromPEMFile(filepath.Join("..", "responder", "testdata", "server_key.pem"))
	require.NoError(t, err)
	return key
}
