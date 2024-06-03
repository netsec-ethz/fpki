package mysql_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"testing"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/stretchr/testify/require"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/db/mysql"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/netsec-ethz/fpki/pkg/tests/random"
	"github.com/netsec-ethz/fpki/pkg/tests/testdb"
	"github.com/netsec-ethz/fpki/pkg/util"
)

// TestUpdateCerts checks that the UpdateCerts function in DB works as expected.
func TestUpdateCerts(t *testing.T) {
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

	certs, certIds, parentIds, names :=
		random.BuildTestRandomUniqueCertsTree(t, random.RandomLeafNames(t, 2)...)
	_ = names
	err := conn.UpdateCerts(
		ctx,
		certIds,
		parentIds,
		util.ExtractExpirations(certs),
		util.ExtractPayloads(certs),
	)
	require.NoError(t, err)

	// Check contents of the certs table.
	gotIds, gotParents, gotExpirations, gotPayloads := getAllCertsTable(ctx, t, conn)
	require.Equal(t, len(certIds), len(gotIds))
	require.ElementsMatch(t, gotIds, certIds)
	require.ElementsMatch(t, parentIds, gotParents)
	require.ElementsMatch(t, util.ExtractExpirations(certs), gotExpirations)
	require.ElementsMatch(t, util.ExtractPayloads(certs), gotPayloads)
}

// TestUpdateCertsNonUnique is similar to TestUpdateCerts but it attempts to insert many
// certificates with the same ID (namely, the c0 and c1 ones).
func TestUpdateCertsNonUnique(t *testing.T) {
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

	certs, certIds, parentIds, names :=
		random.BuildTestRandomCertTree(t, random.RandomLeafNames(t, 2)...)
	_ = names
	expirations := util.ExtractExpirations(certs)
	payloads := util.ExtractPayloads(certs)
	err := conn.UpdateCerts(
		ctx,
		certIds,
		parentIds,
		expirations,
		payloads,
	)
	require.NoError(t, err)

	// The result of the call to BuildTestRandomCertTree contains c0 and c1 multiple times.
	// Remove them.
	expectedIds := certIds[:2]
	expectedParents := parentIds[:2]
	expectedExpirations := expirations[:2]
	expectedPayloads := payloads[:2]
	for i := 2; i < len(certIds); i += 3 {
		expectedIds = append(expectedIds, certIds[i])
		expectedParents = append(expectedParents, parentIds[i])
		expectedExpirations = append(expectedExpirations, expirations[i])
		expectedPayloads = append(expectedPayloads, payloads[i])
	}

	// Check contents of the certs table.
	gotIds, gotParents, gotExpirations, gotPayloads := getAllCertsTable(ctx, t, conn)
	require.Equal(t, len(expectedIds), len(gotIds))
	require.ElementsMatch(t, gotIds, expectedIds)
	require.ElementsMatch(t, expectedParents, gotParents)
	require.ElementsMatch(t, expectedExpirations, gotExpirations)
	require.ElementsMatch(t, expectedPayloads, gotPayloads)
}

func TestCheckCertsExist(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Second)
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

	ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Second)
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
	ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Second)
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
		expectedPols[i], err = pol.Raw()
		require.NoError(t, err)
	}
	require.Equal(t, expectedPols, gotPols)
	// Do the same one by one:
	for i := range expectedPols {
		gotPols, err := conn.RetrievePolicyPayloads(ctx, polIDs[i:i+1])
		require.NoError(t, err)
		require.Equal(t, expectedPols[i:i+1], gotPols)
	}

	// Do the same for combined retrieval of certificate and policies.
	// prepare test data
	certOrPolIDs := make([]*common.SHA256Output, len(certs)+len(pols))
	for i, certID := range certIDs {
		certOrPolIDs[i] = certID
	}
	for i, polID := range polIDs {
		certOrPolIDs[len(certIDs)+i] = polID
	}
	expectedCertsOrPols := make([][]byte, len(certs)+len(pols))
	for i, cert := range certs {
		expectedCertsOrPols[i] = cert.Raw
	}
	for i, pol := range pols {
		expectedCertsOrPols[len(certs)+i], err = pol.Raw()
		require.NoError(t, err)
	}

	// check results
	gotCertsOrPols, err := conn.RetrieveCertificateOrPolicyPayloads(ctx, certOrPolIDs)
	require.NoError(t, err)
	require.ElementsMatch(t, expectedCertsOrPols, gotCertsOrPols)
	// Do the same one by one:
	for i := range expectedCertsOrPols {
		gotCertsOrPols, err := conn.RetrieveCertificateOrPolicyPayloads(ctx, certOrPolIDs[i:i+1])
		require.NoError(t, err)
		require.ElementsMatch(t, expectedCertsOrPols[i:i+1], gotCertsOrPols)
	}
}

func TestLastCTlogServerState(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Second)
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
	// Modify b.com chains: only the 2 leaf certificates.
	c := certs[4*1+2]                               // first chain of b.com (b.com->c1->c0)
	require.Equal(t, "b.com", c.Subject.CommonName) // assert that the test data is still correct.
	c.NotAfter = expiredTime
	c = certs[4*1+3]                                // second chain of b.com (b.com->c0)
	require.Equal(t, "b.com", c.Subject.CommonName) // assert that the test data is still correct.
	c.NotAfter = expiredTime
	// Modify c.com chains: only the single root of its two chains.
	c = certs[4*2]                                   // root of both chains for c.com
	require.Equal(t, "c0.com", c.Subject.CommonName) // assert that the test data is still correct.
	c.NotAfter = expiredTime

	// Ingest data into DB: certs, domains, domain_certs, policies, etc. updated.
	err := updater.UpdateWithKeepExisting(ctx, conn, names, certIDs, parentIDs,
		certs, util.ExtractExpirations(certs), nil)
	require.NoError(t, err)
	// Coalescing of payloads.
	err = conn.RecomputeDirtyDomainsCertAndPolicyIDs(ctx)
	require.NoError(t, err)
	// Cleanup dirty table, as we do with a regular ingest at the end.
	err = conn.CleanupDirty(ctx)
	require.NoError(t, err)

	// Now test that prune removes the two leaves from b.com and four certificates from c.com,
	// because removing the root certificate triggers removal of all descendants.
	t.Logf("Using expired time: %s", now)
	err = conn.PruneCerts(ctx, now)
	require.NoError(t, err)

	// Find out how many certs we have now.
	// We should subtract two leafs in b.com + all certs from c.com
	newCertIDs := getAllCertIds(ctx, t, conn)
	require.Equal(t, len(certs)-(2+4), len(newCertIDs))
	// The certs that remain should correspond to:
	// a.com: 4 certs
	// b.com: 2 certs (non leaf certs c0 and c1)
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
	require.Len(t, dirtyDomains, 4) // (c0.com,c1.com,b.com) + c.com
}

func TestRetrieveDomainEntries(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelF()

	// Configure a test DB.
	config, removeF := testdb.ConfigureTestDB(t)
	defer removeF()

	// Connect to the DB.
	conn := testdb.Connect(t, config)
	defer conn.Close()

	c := mysql.NewMysqlDBForTests(conn)

	// Add a bunch of entries into the `domain_payloads` table.
	// The domain_id will start at 1, the cert_id at 1_000_000 + 1, and the policy at 2_000_000.
	N := 100_000
	domainIDs, certIDs, polIDs := mockDomainData(N)
	insertIntoDomainPayloads(ctx, t, c, domainIDs, certIDs, polIDs)
	// Insert into dirty to use the in-DB-join functionality.
	insertIntoDirty(ctx, conn, "dirty", domainIDs)
	t.Logf("Added mock data to domain_payloads at %s", time.Now().Format(time.StampMilli))

	// Retrieve them using the concurrent RetrieveDomainEntries.
	parallel, err := c.RetrieveDirtyDomainEntriesParallel(ctx, domainIDs)
	require.NoError(t, err)
	t.Logf("Got data from parallel retrieve at %s", time.Now().Format(time.StampMilli))

	joined, err := c.RetrieveDirtyDomainEntriesInDBJoin(ctx, 0, uint64(len(domainIDs)))
	require.NoError(t, err)
	t.Logf("Got data from db join retrieve at %s", time.Now().Format(time.StampMilli))

	// Check against domains from the sequential retrieveDomainEntries function.
	expected, err := c.RetrieveDirtyDomainEntriesSequential(ctx, domainIDs)
	require.NoError(t, err)
	t.Logf("Got data from serial retrieve at %s", time.Now().Format(time.StampMilli))

	kvElementsMatch(t, expected, parallel, "len(expected)=%d,len(got)=%d",
		len(expected), len(parallel))
	require.NotSame(t, expected, parallel)
	kvElementsMatch(t, expected, joined, "len(expected)=%d,len(got)=%d",
		len(expected), len(parallel))
	require.NotSame(t, expected, joined)
}

func TestInsertDomainsIntoDirty(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelF()

	// Configure a test DB.
	config, removeF := testdb.ConfigureTestDB(t)
	defer removeF()

	// Connect to the DB.
	conn := testdb.Connect(t, config)
	defer conn.Close()

	c := mysql.NewMysqlDBForTests(conn)

	// Create a bunch of mock domain IDs, and insert them into the dirty table.
	N := 1_000
	domainIds := random.RandomIDsForTest(t, N)
	err := c.InsertDomainsIntoDirty(ctx, domainIds)
	require.NoError(t, err)

	// Check they were inserted correctly.
	// 1. Retrieve.
	str := "SELECT domain_id FROM dirty"
	rows, err := c.DB().QueryContext(ctx, str)
	require.NoError(t, err)
	require.NoError(t, rows.Err())
	// Each ID.
	gotIds := make([]*common.SHA256Output, 0)
	for rows.Next() {
		var id []byte
		err := rows.Scan(&id)
		require.NoError(t, err)
		require.Equal(t, common.SHA256Size, len(id))
		gotIds = append(gotIds, (*common.SHA256Output)(id))
	}
	// 2. Compare them.
	require.Equal(t, len(domainIds), len(gotIds))
	require.ElementsMatch(t, domainIds, gotIds)
}

func TestUpdateDomains(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelF()

	// Configure a test DB.
	config, removeF := testdb.ConfigureTestDB(t)
	defer removeF()

	// Connect to the DB.
	conn := testdb.Connect(t, config)
	defer conn.Close()

	c := mysql.NewMysqlDBForTests(conn)

	// Create a bunch of mock domain IDs, and insert them into the dirty table.
	N := 1_000
	expectedIds := random.RandomIDsForTest(t, N)
	err := c.InsertDomainsIntoDirty(ctx, expectedIds)
	require.NoError(t, err)

	expectedNames := random.RandomLeafNames(t, N)
	err = c.UpdateDomains(ctx, expectedIds, expectedNames)
	require.NoError(t, err)

	// Function to tie id with name.
	type pair struct {
		id   *common.SHA256Output
		name string
	}
	idsNames2Pairs := func(ids []*common.SHA256Output, names []string) []pair {
		// Tie id with name.
		s := make([]pair, len(ids))
		for i := range ids {
			s[i] = pair{
				id:   ids[i],
				name: names[i],
			}
		}
		return s
	}

	// Check they were inserted correctly.
	// 1. Retrieve.
	str := "SELECT domain_id,domain_name FROM domains"
	rows, err := c.DB().QueryContext(ctx, str)
	require.NoError(t, err)
	require.NoError(t, rows.Err())
	// Each ID.
	gotIds := make([]*common.SHA256Output, 0)
	gotNames := make([]string, 0)
	for rows.Next() {
		var id []byte
		var name string
		err := rows.Scan(&id, &name)
		require.NoError(t, err)

		require.Equal(t, common.SHA256Size, len(id))
		gotIds = append(gotIds, (*common.SHA256Output)(id))
		gotNames = append(gotNames, name)
	}
	// 2. Compare them.
	require.Equal(t, len(expectedIds), len(gotIds))
	expected := idsNames2Pairs(expectedIds, expectedNames)
	got := idsNames2Pairs(gotIds, gotNames)
	require.ElementsMatch(t, expected, got)
}

func BenchmarkRetrieveDomainEntries(b *testing.B) {
	ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancelF()

	// Configure a test DB.
	config, removeF := testdb.ConfigureTestDB(b)
	defer removeF()

	// Connect to the DB.
	conn := testdb.Connect(b, config)
	defer conn.Close()
	c := mysql.NewMysqlDBForTests(conn)

	N := 1_000_000

	domainIDs, certIDs, polIDs := mockDomainData(N)
	insertIntoDomainPayloads(ctx, b, c, domainIDs, certIDs, polIDs)
	// Insert into dirty to use the in-DB-join functionality.
	insertIntoDirty(ctx, conn, "dirty", domainIDs)
	b.Logf("Added mock data to domain_payloads at %s", time.Now().Format(time.StampMilli))

	bdr := benchDomainRetrieval{
		b:   b,
		ctx: ctx,
	}
	for i := 600_000; i <= 1_000_000; i += 100_000 {
		str := fmt.Sprintf("querying-%d00K-", i/100_000)
		b.Run(str+"parallel", func(b *testing.B) {
			bdr.run(func(ctx context.Context) ([]*db.KeyValuePair, error) {
				return c.RetrieveDirtyDomainEntriesParallel(ctx, domainIDs[:i])
			})
		})
		require.Greater(b, bdr.count, 0)

		b.Run(str+"sequential", func(b *testing.B) {
			bdr.run(func(ctx context.Context) ([]*db.KeyValuePair, error) {
				return c.RetrieveDirtyDomainEntriesSequential(ctx, domainIDs[:i])
			})
		})
		require.Greater(b, bdr.count, 0)

		b.Run(str+"dirty-join", func(b *testing.B) {
			bdr.run(func(ctx context.Context) ([]*db.KeyValuePair, error) {
				return c.RetrieveDirtyDomainEntriesInDBJoin(ctx, 0, uint64(i))
			})
		})
		require.Greater(b, bdr.count, 0)
	}
}

type benchDomainRetrieval struct {
	b     *testing.B
	ctx   context.Context
	count int
}

func (b *benchDomainRetrieval) run(
	fcn func(context.Context) ([]*db.KeyValuePair, error),
) {
	b.b.ResetTimer()
	count := 0
	for i := 0; i < b.b.N; i++ {
		kv, err := fcn(b.ctx)
		require.NoError(b.b, err)
		require.NotEmpty(b.b, kv)
		// Do something with the key values to avoid compiler dead code optimization.
		for _, kv := range kv {
			count += len(kv.Value)
		}
	}
	b.count = count
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
		raw, err := pol.Raw()
		require.NoError(t, err)
		id := common.SHA256Hash32Bytes(raw)
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

func getAllCertIds(ctx context.Context, t tests.T, conn testdb.Conn) []*common.SHA256Output {
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

func getAllCertsTable(ctx context.Context, t tests.T, conn db.Conn) (
	ids []*common.SHA256Output,
	parentIds []*common.SHA256Output,
	expirations []*time.Time,
	payloads [][]byte,
) {
	ids = make([]*common.SHA256Output, 0)
	parentIds = make([]*common.SHA256Output, 0)
	expirations = make([]*time.Time, 0)
	payloads = make([][]byte, 0)

	str := "SELECT cert_id,parent_id,expiration,payload FROM certs"
	rows, err := conn.DB().QueryContext(ctx, str)
	require.NoError(t, err)
	require.NoError(t, rows.Err())
	for rows.Next() {
		var id, parent []byte
		var expiration time.Time
		var payload []byte

		err := rows.Scan(&id, &parent, &expiration, &payload)
		require.NoError(t, err)

		ids = append(ids, (*common.SHA256Output)(id))
		if len(parent) == 0 {
			parentIds = append(parentIds, nil)
		} else {
			parentIds = append(parentIds, (*common.SHA256Output)(parent))
		}
		expirations = append(expirations, &expiration)
		payloads = append(payloads, payload)
	}
	return
}

// kvElementsMatch acts as require.ElementsMatch, but faster (no reflection).
func kvElementsMatch(t tests.T, expected, got []*db.KeyValuePair, args ...any) {
	t.Helper()
	A := make(map[common.SHA256Output][]byte)
	for _, x := range expected {
		A[x.Key] = x.Value
	}
	B := make(map[common.SHA256Output][]byte)
	for _, x := range got {
		B[x.Key] = x.Value
	}

	if len(A) != len(B) {
		require.FailNow(t, fmt.Sprintf("different lengths expected=%d, got=%d", len(A), len(B)),
			args...)
	}
	for k, a := range A {
		b, ok := B[k]
		if !ok {
			require.FailNow(t, "different keys", args...)
		}
		if !bytes.Equal(a, b) {
			require.FailNow(t, fmt.Sprintf("different value for key %s", hex.EncodeToString(k[:])),
				args...)
		}
	}
}

func mockDomainData(N int) (
	domainIDs []*common.SHA256Output,
	certIDs []*common.SHA256Output,
	polIDs []*common.SHA256Output,
) {

	domainIDs = make([]*common.SHA256Output, N)
	certIDs = make([]*common.SHA256Output, N)
	polIDs = make([]*common.SHA256Output, N)
	for i := uint64(0); i < uint64(N); i++ {
		domainID := new(common.SHA256Output)
		binary.LittleEndian.PutUint64(domainID[:], i+1)
		domainIDs[i] = domainID

		certID := new(common.SHA256Output)
		binary.LittleEndian.PutUint64(certID[:], i+1_000_001)
		certIDs[i] = certID

		polID := new(common.SHA256Output)
		binary.LittleEndian.PutUint64(polID[:], i+2_000_001)
		polIDs[i] = polID
	}
	return
}

func insertIntoDomainPayloads(
	ctx context.Context,
	t tests.T,
	conn db.Conn,
	domainIDs []*common.SHA256Output,
	certIDs []*common.SHA256Output,
	polIDs []*common.SHA256Output,
) {

	batchSize := 10_000
	N := len(domainIDs)
	for i := 0; i < N; {
		s := i
		e := min(s+batchSize, N)
		W := e - s

		// Convert pointers to byte slices.
		data := make([]interface{}, 3*W)
		for d := 0; d < W; d++ {
			domainID := *domainIDs[i+d] // local copy
			certID := *certIDs[i+d]
			polID := *polIDs[i+d]

			data[3*d+0] = domainID[:]
			data[3*d+1] = certID[:]
			data[3*d+2] = polID[:]
		}

		// Insert into DB and check.
		res, err := conn.DB().ExecContext(ctx,
			"INSERT INTO domain_payloads (domain_id,cert_ids,policy_ids) VALUES "+
				mysql.RepeatStmt(W, 3),
			data...)
		require.NoError(t, err)
		n, err := res.RowsAffected()
		require.NoError(t, err)
		require.Equal(t, int64(W), n)

		// Continue with next batch.
		i = e
	}
}
