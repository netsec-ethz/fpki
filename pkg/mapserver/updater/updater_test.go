package updater

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/rand"
	"testing"
	"time"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/tests/random"
	"github.com/netsec-ethz/fpki/pkg/tests/testdb"
	"github.com/netsec-ethz/fpki/pkg/util"
)

// TestUpdateWithKeepExisting checks that the UpdateWithKeepExisting function can update a large
// number of certificates and policy objects.
func TestUpdateWithKeepExisting(t *testing.T) {
	// Because we are using "random" bytes deterministically here, set a fixed seed.
	rand.Seed(111)

	ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelF()

	// Configure a test DB.
	config, removeF := testdb.ConfigureTestDB(t)
	defer removeF()

	// Connect to the DB.
	conn := testdb.Connect(t, config)
	defer conn.Close()

	// leafCerts contains the names of the leaf certificates we will test.
	leafCerts := []string{
		"leaf.certs.com",
		"example.certs.com",
	}
	// Add many more leaf certificates for the test.
	for i := 0; i < 20000; i++ {
		leafCerts = append(leafCerts, fmt.Sprintf("leaf-%d.auto.certs.com", i+1))
	}

	// Create a random certificate test hierarchy for each leaf.
	var certs []*ctx509.Certificate
	var certIDs, parentCertIDs []*common.SHA256Output
	var certNames [][]string
	for _, leaf := range leafCerts {
		// Create two mock x509 chains on top of leaf:
		certs2, certIDs2, parentCertIDs2, certNames2 := random.BuildTestRandomCertHierarchy(t, leaf)
		certs = append(certs, certs2...)
		certIDs = append(certIDs, certIDs2...)
		parentCertIDs = append(parentCertIDs, parentCertIDs2...)
		certNames = append(certNames, certNames2...)
	}

	// Ingest two mock policies.
	pols := random.BuildTestRandomPolicyHierarchy(t, "a-domain-name.thing")

	// Update with certificates and policies.
	t0 := time.Now()
	err := UpdateWithKeepExisting(ctx, conn, certNames, certIDs, parentCertIDs,
		certs, util.ExtractExpirations(certs), pols)
	require.NoError(t, err)
	t.Logf("time needed to update %d certificates: %s", len(certIDs), time.Since(t0))

	// Coalescing of payloads.
	err = CoalescePayloadsForDirtyDomains(ctx, conn)
	require.NoError(t, err)

	// Check the certificate coalescing: under leaf there must be 4 IDs, for the certs.
	for i, leaf := range leafCerts {
		domainID := common.SHA256Hash32Bytes([]byte(leaf))
		// t.Logf("%s: %s", leaf, hex.EncodeToString(domainID[:]))
		gotCertIDsID, gotCertIDs, err := conn.RetrieveDomainCertificatesIDs(ctx, domainID)
		require.NoError(t, err)
		expectedSize := common.SHA256Size * len(certs) / len(leafCerts)
		require.Len(t, gotCertIDs, expectedSize, "bad length, should be %d but it's %d",
			expectedSize, len(gotCertIDs))
		// From the certificate IDs, grab the IDs corresponding to this leaf:
		N := len(certIDs) / len(leafCerts) // IDs per leaf = total / leaf_count
		expectedCertIDs, expectedCertIDsID := glueSortedIDsAndComputeItsID(certIDs[i*N : (i+1)*N])
		// t.Logf("expectedCertIDs:\t%s\n", hex.EncodeToString(expectedCertIDs))
		// t.Logf("gotCertIDs:     \t%s\n", hex.EncodeToString(gotCertIDs))
		require.Equal(t, expectedCertIDs, gotCertIDs)
		require.Equal(t, expectedCertIDsID, gotCertIDsID)
	}

	// Check policy coalescing.
	policiesPerName := make(map[string][]common.PolicyDocument, len(pols))
	for _, pol := range pols {
		policiesPerName[pol.Domain()] = append(policiesPerName[pol.Domain()], pol)
	}
	for name, policies := range policiesPerName {
		id := common.SHA256Hash32Bytes([]byte(name))
		gotPolIDsID, gotPolIDs, err := conn.RetrieveDomainPoliciesIDs(ctx, id)
		require.NoError(t, err)
		// For each sequence of policies, compute the ID of their JSON.
		polIDs := computeIDsOfPolicies(policies)
		expectedPolIDs, expectedPolIDsID := glueSortedIDsAndComputeItsID(polIDs)
		t.Logf("expectedPolIDs: %s\n", hex.EncodeToString(expectedPolIDs))
		require.Equal(t, expectedPolIDs, gotPolIDs)
		require.Equal(t, expectedPolIDsID, gotPolIDsID)
	}
}

func TestRunWhenFalse(t *testing.T) {
	cases := map[string]struct {
		presence   []bool
		fromParams []int
		toParams   []int
	}{
		"empty": {
			fromParams: []int{},
			toParams:   []int{},
		},
		"one": {
			presence:   []bool{false},
			fromParams: []int{0},
			toParams:   []int{0},
		},
		"one_true": {
			presence:   []bool{true},
			fromParams: []int{},
			toParams:   []int{},
		},
		"010": {
			presence:   []bool{false, true, false},
			fromParams: []int{0, 2},
			toParams:   []int{0, 1},
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			gotTo := make([]int, 0)
			gotFrom := make([]int, 0)
			runWhenFalse(tc.presence, func(to, from int) {
				gotTo = append(gotTo, to)
				gotFrom = append(gotFrom, from)
			})
			assert.Equal(t, tc.fromParams, gotFrom)
			assert.Equal(t, tc.toParams, gotTo)
		})
	}
}

// TestMapUpdaterStartFetching checks that the updater is able to keep a tally of which indices have been
// already updated and write them down in the DB.
func TestMapUpdaterStartFetching(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelF()

	// Configure a test DB.
	config, removeF := testdb.ConfigureTestDB(t)
	defer removeF()

	url := "myURL"
	updater, err := NewMapUpdater(config, url)
	require.NoError(t, err)

	// Replace fetcher with a mock one.
	onReturnNextBatchCalls := int64(0)
	onStopFetchingCalls := 0
	batchSize := int64(1)
	fetcher := &mockFetcher{}
	fetcher = &mockFetcher{
		url:  url,
		size: 0,
		onNextBatch: func(ctx context.Context) bool {
			// Returns elements in batchSize: still something to return if size not reached.
			return fetcher.size-onReturnNextBatchCalls*batchSize > 0
		},
		onReturnNextBatch: func() (
			[]*ctx509.Certificate, // certs
			[][]*ctx509.Certificate, // chains
			error,
		) {
			// Return a slice of nil certs and chains, with the correct size.
			onReturnNextBatchCalls++
			// The n variable is the number of items to return.
			n := batchSize
			if (onReturnNextBatchCalls * batchSize) > fetcher.size {
				n = fetcher.size % batchSize
			}
			return make([]*ctx509.Certificate, n),
				make([][]*ctx509.Certificate, n),
				nil
		},
		onStopFetching: func() {
			onStopFetchingCalls++
		},
	}
	updater.Fetcher = fetcher

	// Because every call to NextBatch is potentially blocking, we need to wrap it around a
	// function that can timeout.
	nextBatch := func() bool {
		res := make(chan bool)
		go func() {
			res <- updater.NextBatch(ctx)
		}()
		select {
		case <-ctx.Done():
			require.FailNow(t, "NextBatch didn't finish")
			return false
		case r := <-res:
			return r
		}
	}

	// We will need a DB connection to check internal values later.
	conn := testdb.Connect(t, config)
	defer conn.Close()

	// Case 1: Size is 0
	updater.StartFetching(0, 999)
	for nextBatch() {
		require.FailNow(t, "there should not be any iteration")
	}
	// Check that the StopFetching method has not been called yet.
	require.Equal(t, 0, onStopFetchingCalls)
	updater.StopFetching()
	fetcher.onStopFetching = nil // Remove the hook

	// Check number of calls to ReturnNextBatch.
	require.Equal(t, fetcher.size, min(fetcher.size, onReturnNextBatchCalls*batchSize))
	// Check that we stored the current size.
	lastIndex, err := conn.LastCertIndexWritten(ctx, url)
	require.NoError(t, err)
	require.Equal(t, fetcher.size, lastIndex+1)

	// Case 2: Size is 12, batch still is 1.
	onReturnNextBatchCalls = 0
	fetcher.size = 12
	updater.StartFetching(0, 1000)
	for nextBatch() {
		_, err := updater.UpdateNextBatch(ctx)
		require.NoError(t, err)
		// Check that at every batch we store the last index.
		lastIndex, err = conn.LastCertIndexWritten(ctx, url)
		require.NoError(t, err)
		require.Equal(t,
			min(fetcher.size, onReturnNextBatchCalls*batchSize),
			lastIndex+1)
	}
	updater.StopFetching()
	// Check number of calls to ReturnNextBatch.
	require.Equal(t, fetcher.size, min(fetcher.size, onReturnNextBatchCalls*batchSize))
	// Check that we stored the current size.
	lastIndex, err = conn.LastCertIndexWritten(ctx, url)
	require.NoError(t, err)
	require.Equal(t, fetcher.size, lastIndex+1)

	// Case 2: Size is 12, batch is 5.
	onReturnNextBatchCalls = 0
	fetcher.size = 12
	batchSize = 5
	// Reset the size for this CT log server:
	err = conn.UpdateLastCertIndexWritten(ctx, url, -1)
	require.NoError(t, err)
	updater.StartFetching(0, 1000)
	for nextBatch() {
		_, err := updater.UpdateNextBatch(ctx)
		require.NoError(t, err)
		// Check that at every batch we store the last index.
		lastIndex, err = conn.LastCertIndexWritten(ctx, url)
		require.NoError(t, err)
		require.Equal(t,
			min(fetcher.size, onReturnNextBatchCalls*batchSize),
			lastIndex+1)
	}
	updater.StopFetching()
	// Check number of calls to ReturnNextBatch.
	require.Equal(t, fetcher.size, min(fetcher.size, onReturnNextBatchCalls*batchSize))
	// Check that we stored the current size.
	lastIndex, err = conn.LastCertIndexWritten(ctx, url)
	require.NoError(t, err)
	require.Equal(t, fetcher.size, lastIndex+1)
}

// TestMapUpdaterStartFetchingRemaining checks that after a full round of updates, the next call
// to StartFetchingRemaining continues with the last unfetched index.
func TestMapUpdaterStartFetchingRemaining(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelF()

	// Configure a test DB.
	config, removeF := testdb.ConfigureTestDB(t)
	defer removeF()

	url := "myURL"
	updater, err := NewMapUpdater(config, url)
	require.NoError(t, err)

	// Replace fetcher with a mock one.
	gotStart := int64(0)
	gotEnd := int64(0)
	onReturnNextBatchCalls := int64(0)
	fetcher := &mockFetcher{} // to be able to reference `fetcher` below
	fetcher = &mockFetcher{
		url:  url,
		size: 10,
		onStartFetching: func(startIndex, endIndex int64) {
			gotStart, gotEnd = startIndex, endIndex
		},
		onNextBatch: func(ctx context.Context) bool {
			// Returns elements in batchSize: still something to return if size not reached.
			return fetcher.size-onReturnNextBatchCalls > 0
		},
		onReturnNextBatch: func() ([]*ctx509.Certificate, [][]*ctx509.Certificate, error) {
			// Return one cert and chain.
			onReturnNextBatchCalls++
			return make([]*ctx509.Certificate, 1), make([][]*ctx509.Certificate, 1), nil
		},
	}
	updater.Fetcher = fetcher

	// Start fetching remaining. Because this is the first time, it should fetch them all.
	err = updater.StartFetchingRemaining()
	require.NoError(t, err)
	for updater.NextBatch(ctx) {
		_, err = updater.UpdateNextBatch(ctx)
		require.NoError(t, err)
	}
	// Check that it fetched them all.
	require.Equal(t, int64(0), gotStart)
	require.Equal(t, fetcher.size-1, gotEnd)
	require.Equal(t, fetcher.size, onReturnNextBatchCalls)
	lastEntry := fetcher.size - 1
	updater.StopFetching()

	// After e.g. a day, the sie of the CT log has increased.
	fetcher.size += 5
	err = updater.StartFetchingRemaining()
	require.NoError(t, err)
	extraTimes := 0
	for ; updater.NextBatch(ctx); extraTimes++ {
		_, err = updater.UpdateNextBatch(ctx)
		require.NoError(t, err)
	}
	// Check that we only called NextBatch and ReturnNextBatch the expected times.
	require.Equal(t, 5, extraTimes)
	// Check that it started from the first not seen entry, until the end of the CT log.
	require.Equal(t, lastEntry+1, gotStart)
	require.Equal(t, fetcher.size-1, gotEnd)
	require.Equal(t, fetcher.size, onReturnNextBatchCalls)
	updater.StopFetching()
}

func glueSortedIDsAndComputeItsID(IDs []*common.SHA256Output) ([]byte, *common.SHA256Output) {
	gluedIDs := common.SortIDsAndGlue(IDs)
	// Compute the hash of the glued IDs.
	id := common.SHA256Hash32Bytes(gluedIDs)
	return gluedIDs, &id
}

func computeIDsOfPolicies(policies []common.PolicyDocument) []*common.SHA256Output {
	set := make(map[common.SHA256Output]struct{}, len(policies))
	for _, pol := range policies {
		id := common.SHA256Hash32Bytes(pol.Raw())
		set[id] = struct{}{}
	}

	IDs := make([]*common.SHA256Output, 0, len(set))
	for k := range set {
		k := k
		IDs = append(IDs, &k)
	}
	return IDs
}

type mockFetcher struct {
	url               string
	size              int64
	onStartFetching   func(startIndex, endIndex int64)
	onStopFetching    func()
	onNextBatch       func(ctx context.Context) bool
	onReturnNextBatch func() ([]*ctx509.Certificate, [][]*ctx509.Certificate, error)
}

func (f *mockFetcher) URL() string {
	return f.url
}

func (f *mockFetcher) GetSize(ctx context.Context) (uint64, error) {
	return uint64(f.size), nil
}

func (f *mockFetcher) StartFetching(startIndex, endIndex int64) {
	if f.onStartFetching != nil {
		f.onStartFetching(startIndex, endIndex)
	}
}

func (f *mockFetcher) StopFetching() {
	if f.onStopFetching != nil {
		f.onStopFetching()
	}
}

func (f *mockFetcher) NextBatch(ctx context.Context) bool {
	return f.onNextBatch(ctx)
}

func (f *mockFetcher) ReturnNextBatch() ([]*ctx509.Certificate, [][]*ctx509.Certificate, error) {
	return f.onReturnNextBatch()
}

func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
