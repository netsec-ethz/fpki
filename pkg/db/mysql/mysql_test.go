package mysql_test

import (
	"context"
	"encoding/hex"
	"math/rand"
	"os"
	"testing"
	"time"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/stretchr/testify/require"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/db/mysql"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	"github.com/netsec-ethz/fpki/pkg/tests/testdb"
	"github.com/netsec-ethz/fpki/pkg/util"
)

func TestCoalesceForDirtyDomains(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	// DB will have the same name as the test function.
	dbName := t.Name()
	config := db.NewConfig(mysql.WithDefaults(), db.WithDB(dbName))

	// Create a new DB with that name. On exiting the function, it will be removed.
	err := testdb.CreateTestDB(ctx, dbName)
	require.NoError(t, err)
	defer func() {
		err = testdb.RemoveTestDB(ctx, config)
		require.NoError(t, err)
	}()

	// Connect to the DB.
	conn, err := mysql.Connect(config)
	require.NoError(t, err)
	defer conn.Close()

	leafCerts := []string{
		"leaf.certs.com",
		"example.certs.com",
	}
	var certs []*ctx509.Certificate
	var certIDs, parentCertIDs []*common.SHA256Output
	var certNames [][]string
	for _, leaf := range leafCerts {
		// Create two mock x509 chains on top of leaf:
		certs2, certIDs2, parentCertIDs2, certNames2 := testdb.BuildTestCertHierarchy(t, leaf)
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
	err = updater.UpdateWithKeepExisting(ctx, conn, certNames, certIDs, parentCertIDs,
		certs, util.ExtractExpirations(certs), pols)
	require.NoError(t, err)

	// Coalescing of payloads.
	err = updater.CoalescePayloadsForDirtyDomains(ctx, conn)
	require.NoError(t, err)

	// Check the certificate coalescing: under leaf there must be 4 IDs, for the certs.
	for i, leaf := range leafCerts {
		domainID := common.SHA256Hash32Bytes([]byte(leaf))
		gotCertIDsID, gotCertIDs, err := conn.RetrieveDomainCertificatesPayload(ctx, domainID)
		require.NoError(t, err)
		expectedSize := common.SHA256Size * len(certs) / len(leafCerts)
		require.Len(t, gotCertIDs, expectedSize, "bad length, should be %d but it's %d",
			expectedSize, len(gotCertIDs))
		// From the certificate IDs, grab the IDs corresponding to this leaf:
		N := len(certIDs) / len(leafCerts) // IDs per leaf = total / leaf_count
		expectedCertIDs, expectedCertIDsID := glueSortedIDsAndComputeItsID(certIDs[i*N : (i+1)*N])
		t.Logf("expectedCertIDs: %s\n", hex.EncodeToString(expectedCertIDs))
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
		gotPolIDsID, gotPolIDs, err := conn.RetrieveDomainPoliciesPayload(ctx, id)
		require.NoError(t, err)
		// For each sequence of policies, compute the ID of their JSON.
		polIDs := computeIDsOfPolicies(policies)
		expectedPolIDs, expectedPolIDsID := glueSortedIDsAndComputeItsID(polIDs)
		t.Logf("expectedPolIDs: %s\n", hex.EncodeToString(expectedPolIDs))
		require.Equal(t, expectedPolIDs, gotPolIDs)
		require.Equal(t, expectedPolIDsID, gotPolIDsID)
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

func randomBytes(t require.TestingT, size int) []byte {
	buff := make([]byte, size)
	n, err := rand.Read(buff)
	require.NoError(t, err)
	require.Equal(t, size, n)
	return buff
}
