package updater

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/tests/random"
	"github.com/netsec-ethz/fpki/pkg/tests/testdb"
	"github.com/netsec-ethz/fpki/pkg/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	conn, err := testdb.Connect(config)
	require.NoError(t, err)
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
	data, err := os.ReadFile("../../../tests/testdata/2-SPs.json")
	require.NoError(t, err)
	pols, err := util.LoadPoliciesFromRaw(data)
	require.NoError(t, err)

	// Update with certificates and policies.
	t0 := time.Now()
	err = UpdateWithKeepExisting(ctx, conn, certNames, certIDs, parentCertIDs,
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
	policiesPerName := make(map[string][]common.PolicyObject, len(pols))
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

func glueSortedIDsAndComputeItsID(IDs []*common.SHA256Output) ([]byte, *common.SHA256Output) {
	gluedIDs := common.SortIDsAndGlue(IDs)
	// Compute the hash of the glued IDs.
	id := common.SHA256Hash32Bytes(gluedIDs)
	return gluedIDs, &id
}

func computeIDsOfPolicies(policies []common.PolicyObject) []*common.SHA256Output {
	IDs := make([]*common.SHA256Output, len(policies))
	for i, pol := range policies {
		id := common.SHA256Hash32Bytes(pol.Raw())
		IDs[i] = &id
	}
	return IDs
}
