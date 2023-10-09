package mysql_test

import (
	"context"
	"encoding/hex"
	"math/rand"
	"testing"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/stretchr/testify/require"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db/mysql"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/netsec-ethz/fpki/pkg/tests/random"
	"github.com/netsec-ethz/fpki/pkg/tests/testdb"
	"github.com/netsec-ethz/fpki/pkg/util"
)

func TestCheckCertsExist(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	// Configure a test DB.
	config, removeF := testdb.ConfigureTestDB(t)
	defer removeF()

	// Connect to the DB.
	conn, err := testdb.Connect(config)
	require.NoError(t, err)
	defer conn.Close()

	// Obtain a convenient MysqlDBForTests object (only in tests).
	c := mysql.NewMysqlDBForTests(conn)
	createIDs := func(n int) []*common.SHA256Output {
		ids := make([]*common.SHA256Output, n)
		for i := range ids {
			id := common.SHA256Output{}
			ids[i] = &id
		}
		return ids
	}

	// Check the function with 10 elements, it should work.
	N := 10
	ids := createIDs(N)
	presence := make([]bool, N)
	err = c.DebugCheckCertsExist(ctx, ids, presence)
	require.NoError(t, err)

	// Check now with 10000 elements, will fail.
	N = 10000
	ids = createIDs(N)
	presence = make([]bool, N)
	err = c.DebugCheckCertsExist(ctx, ids, presence)
	require.Error(t, err)
	t.Logf("error type is: %T, message: %s", err, err)
	require.IsType(t, &mysqldriver.MySQLError{}, err)
	myErr := err.(*mysqldriver.MySQLError)
	require.Equal(t, myErr.Number, uint16(1436)) // Thread stack overrun.

	// With 10000 elements but using the public function, it will work.
	presence, err = c.CheckCertsExist(ctx, ids)
	require.NoError(t, err)
	require.Len(t, presence, len(ids))
}

func TestCoalesceForDirtyDomains(t *testing.T) {
	// Because we are using "random" bytes deterministically here, set a fixed seed.
	rand.Seed(1)

	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	// Configure a test DB.
	config, removeF := testdb.ConfigureTestDB(t)
	defer removeF()

	// Connect to the DB.
	conn, err := testdb.Connect(config)
	require.NoError(t, err)
	defer conn.Close()

	// Prepare two mock leaf certificates, with their trust chains.
	leafCerts := []string{
		"leaf.certs.com",
		"example.certs.com",
	}
	certs, certIDs, parentCertIDs, certNames := testCertHierarchyForLeafs(t, leafCerts)

	// Prepare a mock policy chain.
	leafPols := []string{
		"domain_with_policies.com",
	}
	pols, polIDs := testPolicyHierarchyForLeafs(t, leafPols)

	// Update with certificates and policies.
	err = updater.UpdateWithKeepExisting(ctx, conn, certNames, certIDs, parentCertIDs,
		certs, util.ExtractExpirations(certs), pols)
	require.NoError(t, err)

	// Coalescing of payloads.
	err = updater.CoalescePayloadsForDirtyDomains(ctx, conn)
	require.NoError(t, err)

	// Check the certificate coalescing: under leaf there must be 4 IDs, for the certs.
	for i, leaf := range leafCerts {
		domainID := common.SHA256Hash32Bytes([]byte(leaf))
		gotCertIDsID, gotCertIDs, err := conn.RetrieveDomainCertificatesIDs(ctx, domainID)
		require.NoError(t, err)
		expectedSize := common.SHA256Size * len(certs) / len(leafCerts)
		require.Len(t, gotCertIDs, expectedSize, "bad length, should be %d but it's %d",
			expectedSize, len(gotCertIDs))
		// From the certificate IDs, grab the IDs corresponding to this leaf:
		N := len(certIDs) / len(leafCerts) // IDs per leaf = total / leaf_count
		expectedCertIDs, expectedCertIDsID := glueSortedIDsAndComputeItsID(certIDs[i*N : (i+1)*N])
		t.Logf("Certificate IDs for domain name \"%s\":\nexpected: %s\ngot:      %s",
			leaf, hex.EncodeToString(expectedCertIDs), hex.EncodeToString(gotCertIDs))
		require.Equal(t, expectedCertIDs, gotCertIDs)
		require.Equal(t, expectedCertIDsID, gotCertIDsID)
	}

	// Check policy coalescing.
	for i, leaf := range leafPols {
		domainID := common.SHA256Hash32Bytes([]byte(leaf))
		gotPolIDsID, gotPolIDs, err := conn.RetrieveDomainPoliciesIDs(ctx, domainID)
		require.NoError(t, err)
		expectedSize := common.SHA256Size * len(pols) / len(leafPols)
		require.Len(t, gotPolIDs, expectedSize, "bad length, should be %d but it's %d",
			expectedSize, len(gotPolIDs))
		// From the policy IDs, grab the IDs corresponding to this leaf:
		N := len(polIDs) / len(leafPols)
		expectedPolIDs, expectedPolIDsID := glueSortedIDsAndComputeItsID(polIDs[i*N : (i+1)*N])
		t.Logf("Policy IDs for domain name \"%s\":\nexpected: %s\ngot:      %s",
			leaf, hex.EncodeToString(expectedPolIDs), hex.EncodeToString(gotPolIDs))
		require.Equal(t, expectedPolIDs, gotPolIDs)
		require.Equal(t, expectedPolIDsID, gotPolIDsID)
	}
}

func TestRetrieveCertificatePayloads(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	// Configure a test DB.
	config, removeF := testdb.ConfigureTestDB(t)
	defer removeF()

	// Connect to the DB.
	conn, err := testdb.Connect(config)
	require.NoError(t, err)
	defer conn.Close()

	// Ingest some data.
	leafCerts := []string{
		"leaf.certs.com",
		"example.certs.com",
	}
	certs, certIDs, parentCertIDs, certNames := testCertHierarchyForLeafs(t, leafCerts)
	pols, polIDs := testPolicyHierarchyForLeafs(t, leafCerts)
	err = updater.UpdateWithKeepExisting(ctx, conn, certNames, certIDs, parentCertIDs,
		certs, util.ExtractExpirations(certs), pols)
	require.NoError(t, err)
	// Coalescing of payloads.
	err = updater.CoalescePayloadsForDirtyDomains(ctx, conn)
	require.NoError(t, err)

	// I can retrieve any of the certificate by their IDs.
	gotCerts, err := conn.RetrieveCertificatePayloads(ctx, certIDs)
	require.NoError(t, err)
	expectedCerts := make([][]byte, len(certs))
	for i, cert := range certs {
		expectedCerts[i] = cert.Raw
	}
	require.Equal(t, expectedCerts, gotCerts)
	// Do the same one by one:
	for i := range expectedCerts {
		gotCerts, err := conn.RetrieveCertificatePayloads(ctx, certIDs[i:i+1])
		require.NoError(t, err)
		require.Equal(t, expectedCerts[i:i+1], gotCerts)
	}

	// Do the same for policies.
	gotPols, err := conn.RetrievePolicyPayloads(ctx, polIDs)
	require.NoError(t, err)
	expectedPols := make([][]byte, len(pols))
	for i, pol := range pols {
		expectedPols[i] = pol.Raw()
	}
	require.Equal(t, expectedPols, gotPols)
	// Do the same one by one:
	for i := range expectedPols {
		gotPols, err := conn.RetrievePolicyPayloads(ctx, polIDs[i:i+1])
		require.NoError(t, err)
		require.Equal(t, expectedPols[i:i+1], gotPols)
	}
}

// testCertHierarchyForLeafs returns a hierarchy per leaf certificate. Each certificate is composed
// of two mock chains, like: leaf->c1.com->c0.com, leaf->c0.com , created using the function
// BuildTestRandomCertHierarchy.
func testCertHierarchyForLeafs(t tests.T, leaves []string) (certs []*ctx509.Certificate,
	certIDs, parentCertIDs []*common.SHA256Output, certNames [][]string) {

	for _, leaf := range leaves {
		// Create two mock x509 chains on top of leaf:
		certs2, certIDs2, parentCertIDs2, certNames2 := random.BuildTestRandomCertHierarchy(t, leaf)
		certs = append(certs, certs2...)
		certIDs = append(certIDs, certIDs2...)
		parentCertIDs = append(parentCertIDs, parentCertIDs2...)
		certNames = append(certNames, certNames2...)
	}
	return
}

// testPolicyHierarchyForLeafs returns simply a policy hierarchy per leaf name, created using
// the function BuildTestRandomPolicyHierarchy.
func testPolicyHierarchyForLeafs(t tests.T, leaves []string) (pols []common.PolicyDocument,
	polIDs []*common.SHA256Output) {

	for _, name := range leaves {
		pols = append(pols,
			random.BuildTestRandomPolicyHierarchy(t, name)...)
	}

	polIDs = make([]*common.SHA256Output, len(pols))
	for i, pol := range pols {
		id := common.SHA256Hash32Bytes(pol.Raw())
		polIDs[i] = &id
	}
	return
}

func glueSortedIDsAndComputeItsID(IDs []*common.SHA256Output) ([]byte, *common.SHA256Output) {
	gluedIDs := common.SortIDsAndGlue(IDs)
	// Compute the hash of the glued IDs.
	id := common.SHA256Hash32Bytes(gluedIDs)
	return gluedIDs, &id
}
