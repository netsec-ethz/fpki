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
	conn := testdb.Connect(t, config)
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
	err := c.DebugCheckCertsExist(ctx, ids, presence)
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
	conn := testdb.Connect(t, config)
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
	err := updater.UpdateWithKeepExisting(ctx, conn, certNames, certIDs, parentCertIDs,
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
	conn := testdb.Connect(t, config)
	defer conn.Close()

	// Ingest some data.
	leafCerts := []string{
		"leaf.certs.com",
		"example.certs.com",
	}
	certs, certIDs, parentCertIDs, certNames := testCertHierarchyForLeafs(t, leafCerts)
	pols, polIDs := testPolicyHierarchyForLeafs(t, leafCerts)
	err := updater.UpdateWithKeepExisting(ctx, conn, certNames, certIDs, parentCertIDs,
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

func TestLastCTlogServerState(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	// Configure a test DB.
	config, removeF := testdb.ConfigureTestDB(t)
	defer removeF()

	// Connect to the DB.
	conn := testdb.Connect(t, config)
	defer conn.Close()

	// Check that querying for an unknown URL doesn't fail and returns 0 as its last size:
	n, sth, err := conn.LastCTlogServerState(ctx, "doesnt exist")
	require.NoError(t, err)
	require.Equal(t, int64(0), n)
	require.Nil(t, sth)

	// Store values for two urls.
	url1 := "myurl"
	err = conn.UpdateLastCTlogServerState(ctx, url1, 42, []byte{4, 2})
	require.NoError(t, err)
	url2 := "anotherurl"
	err = conn.UpdateLastCTlogServerState(ctx, url2, 123, []byte{1, 2, 3})
	require.NoError(t, err)

	// Check the stored values.
	n, sth, err = conn.LastCTlogServerState(ctx, url1)
	require.NoError(t, err)
	require.Equal(t, int64(42), n)
	require.Equal(t, sth, []byte{4, 2})
	n, sth, err = conn.LastCTlogServerState(ctx, url2)
	require.NoError(t, err)
	require.Equal(t, int64(123), n)
	require.Equal(t, sth, []byte{1, 2, 3})

	// Replace one value and check it.
	err = conn.UpdateLastCTlogServerState(ctx, url2, 222, []byte{2, 2, 2})
	require.NoError(t, err)
	n, sth, err = conn.LastCTlogServerState(ctx, url2)
	require.NoError(t, err)
	require.Equal(t, int64(222), n)
	require.Equal(t, sth, []byte{2, 2, 2})

	// Unknown urls still give out -1:
	n, sth, err = conn.LastCTlogServerState(ctx, "doesnt exist")
	require.NoError(t, err)
	require.Equal(t, int64(0), n)
	require.Nil(t, sth)
}

func TestPruneCerts(t *testing.T) {
	rand.Seed(322)

	ctx, cancelF := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelF()

	// Configure a test DB.
	config, removeF := testdb.ConfigureTestDB(t)
	defer removeF()

	// Connect to the DB.
	conn := testdb.Connect(t, config)
	defer conn.Close()

	// Prepare test data.
	// a.com 's chain will not expire.
	// b.com 's chain will expire at its leaf.
	// c.com 's chain will expire only its root.
	expiredTime := util.TimeFromSecs(100)
	now := expiredTime.Add(time.Hour)
	leafNames := []string{
		"a.com",
		"b.com",
		"c.com",
	}
	certs, certIDs, parentIDs, names := testCertHierarchyForLeafs(t, leafNames)
	// Check that no certificate is expired yet.
	for i, cert := range certs {
		require.False(t, now.After(cert.NotAfter),
			"failed test data precondition at %d, with value %s",
			i, cert.NotAfter)
	}
	// Check that ensure that the data setup has not changed (leaves at the expected index, etc).
	require.Equal(t, len(leafNames)*4, len(certs))
	require.Equal(t, len(certs), len(certIDs))
	require.Equal(t, len(certs), len(parentIDs))
	require.Equal(t, len(certs), len(names))
	// Modify b.com: only the 2 leaf certificates.
	c := certs[4*1+2]                               // first chain of b.com (b.com->c1->c0)
	require.Equal(t, "b.com", c.Subject.CommonName) // assert that the test data is still correct.
	c.NotAfter = expiredTime
	c = certs[4*1+3]                                // second chain of b.com (b.com->c0)
	require.Equal(t, "b.com", c.Subject.CommonName) // assert that the test data is still correct.
	c.NotAfter = expiredTime
	// Modify c.com: only the single root of its two chains.
	c = certs[4*2]                                   // root of both chains for c.com
	require.Equal(t, "c0.com", c.Subject.CommonName) // assert that the test data is still correct.
	c.NotAfter = expiredTime

	// Ingest data into DB.
	err := updater.UpdateWithKeepExisting(ctx, conn, names, certIDs, parentIDs,
		certs, util.ExtractExpirations(certs), nil)
	require.NoError(t, err)
	// Coalescing of payloads.
	err = updater.CoalescePayloadsForDirtyDomains(ctx, conn)
	require.NoError(t, err)

	err = conn.CleanupDirty(ctx)
	require.NoError(t, err)

	// Now test that prune removes the to leaves from b.com and four certificates from c.com,
	// because removing the root certificate triggers removal of all descendants.
	t.Logf("Using expired time: %s", now)
	err = conn.PruneCerts(ctx, now)
	require.NoError(t, err)
	// Find out how many certs we have now.
	// We should substract two leafs in b.com + all certs from c.com
	newCertIDs := getAllCerts(ctx, t, conn)
	require.Equal(t, len(certs)-((1+1)+(4)), len(newCertIDs))
	// The certs we still have should correspond to 4 from a.com + 2 from b.com (non leaf certs)
	// Create a set of IDs and query them.
	newIDsSet := make(map[common.SHA256Output]struct{})
	for _, id := range newCertIDs {
		newIDsSet[*id] = struct{}{}
	}
	require.Len(t, newIDsSet, len(newCertIDs)) // check the conversion went okay
	// a.com certificates
	require.Contains(t, newIDsSet, *certIDs[4*0+0])
	require.Contains(t, newIDsSet, *certIDs[4*0+1])
	require.Contains(t, newIDsSet, *certIDs[4*0+2])
	require.Contains(t, newIDsSet, *certIDs[4*0+3])
	// b.com
	require.Contains(t, newIDsSet, *certIDs[4*1+0])
	require.Contains(t, newIDsSet, *certIDs[4*1+1])
	require.NotContains(t, newIDsSet, *certIDs[4*1+2])
	require.NotContains(t, newIDsSet, *certIDs[4*1+3])
	// c.com
	require.NotContains(t, newIDsSet, *certIDs[4*2+0])
	require.NotContains(t, newIDsSet, *certIDs[4*2+1])
	require.NotContains(t, newIDsSet, *certIDs[4*2+2])
	require.NotContains(t, newIDsSet, *certIDs[4*2+3])

	// Test the appropriate entries exist in dirty.
	dirtyDomains, err := conn.RetrieveDirtyDomains(ctx)
	require.NoError(t, err)
	require.Len(t, dirtyDomains, 2) // b.com + c.com
}

// testCertHierarchyForLeafs returns a hierarchy per leaf certificate. Each certificate is composed
// of two mock chains, like: leaf->c1.com->c0.com, leaf->c0.com , created using the function
// BuildTestRandomCertHierarchy. That function always returns four certificates, in this order:
// c0.com,c1.com, leaf->c1->c0, leaf->c0
// Thus it always returns 4*len(leaves) entries.
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

func getAllCerts(ctx context.Context, t tests.T, conn testdb.Conn) []*common.SHA256Output {
	rows, err := conn.DB().QueryContext(ctx, "SELECT cert_id FROM certs")
	require.NoError(t, err)
	IDs := make([]*common.SHA256Output, 0)
	for rows.Next() {
		var data []byte
		err = rows.Scan(&data)
		require.NoError(t, err)
		id := *(*common.SHA256Output)(data)
		IDs = append(IDs, &id)
	}
	return IDs
}
