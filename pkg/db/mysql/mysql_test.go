package mysql_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"math/rand"
	"os"
	"sort"
	"testing"
	"time"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
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

	// Use two mock x509 chains:
	certs, certIDs, parentCertIDs, certNames := buildTestCertHierarchy(t)
	err = updater.UpdateCertsWithKeepExisting(ctx, conn, certNames, util.ExtractExpirations(certs),
		certs, certIDs, parentCertIDs)
	require.NoError(t, err)

	// Ingest two mock policies.
	data, err := os.ReadFile("../../../tests/testdata/2-SPs.json")
	require.NoError(t, err)
	pols, polIDs, err := util.LoadPoliciesFromRaw(data)
	require.NoError(t, err)
	var expirations []*time.Time
	err = updater.UpdatePoliciesWithKeepExisting(ctx, conn, certNames, expirations, pols, polIDs)
	require.NoError(t, err)

	// Coalescing of payloads.
	err = updater.CoalescePayloadsForDirtyDomains(ctx, conn)
	require.NoError(t, err)

	// Check the certificate coalescing: under leaf.com there must be 4 IDs, for the certs.
	domainID := common.SHA256Hash32Bytes([]byte("leaf.com"))
	gotCertIDsID, gotCertIDs, err := conn.RetrieveDomainCertificatesPayload(ctx, domainID)
	require.NoError(t, err)
	require.Len(t, gotCertIDs, common.SHA256Size*len(certs))
	expectedCertIDs, expectedCertIDsID := glueSortedIDsAndComputeItsID(certIDs)
	t.Logf("expectedCertIDs: %s\n", hex.EncodeToString(expectedCertIDs))
	require.Equal(t, expectedCertIDs, gotCertIDs)
	require.Equal(t, expectedCertIDsID, gotCertIDsID)
}

// buildTestCertHierarchy returns the certificates, chains, and names for two mock certificate
// chains: the first chain is leaf.com->c1.com->c0.com , and the second chain is
// leaf.com->c0.com .
func buildTestCertHierarchy(t require.TestingT) (
	certs []*ctx509.Certificate, IDs, parentIDs []*common.SHA256Output, names [][]string) {

	// Create all certificates.
	certs = make([]*ctx509.Certificate, 4)
	certs[0] = randomX509Cert(t, "c0.com")
	certs[1] = randomX509Cert(t, "c1.com")
	certs[2] = randomX509Cert(t, "leaf.com")
	certs[3] = randomX509Cert(t, "leaf.com")

	// IDs:
	IDs = make([]*common.SHA256Output, len(certs))
	for i, c := range certs {
		id := common.SHA256Hash32Bytes(c.Raw)
		IDs[i] = &id
	}

	// Names: only c2 and c3 are leaves, the rest should be nil.
	names = make([][]string, len(certs))
	names[2] = certs[2].DNSNames
	names[3] = certs[3].DNSNames

	// Parent IDs.
	parentIDs = make([]*common.SHA256Output, len(certs))
	// First chain:
	parentIDs[1] = IDs[0]
	parentIDs[2] = IDs[1]
	// Second chain:
	parentIDs[3] = IDs[0]

	return
}

func glueSortedIDsAndComputeItsID(certIDs []*common.SHA256Output) ([]byte, *common.SHA256Output) {
	// Copy slice to avoid mutating of the original.
	IDs := append(certIDs[:0:0], certIDs...)
	// Sort the IDs.
	sort.Slice(IDs, func(i, j int) bool {
		return bytes.Compare(IDs[i][:], IDs[j][:]) == -1
	})
	// Glue the sorted IDs.
	gluedIDs := make([]byte, common.SHA256Size*len(IDs))
	for i, id := range IDs {
		copy(gluedIDs[i*common.SHA256Size:], id[:])
	}
	// Compute the hash of the glued IDs.
	id := common.SHA256Hash32Bytes(gluedIDs)
	return gluedIDs, &id
}

func randomX509Cert(t require.TestingT, domain string) *ctx509.Certificate {
	return &ctx509.Certificate{
		DNSNames: []string{domain},
		Subject: pkix.Name{
			CommonName: domain,
		},
		NotBefore: util.TimeFromSecs(0),
		NotAfter:  time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC),
		Raw:       randomBytes(t, 10),
	}
}

func randomBytes(t require.TestingT, size int) []byte {
	buff := make([]byte, size)
	n, err := rand.Read(buff)
	require.NoError(t, err)
	require.Equal(t, size, n)
	return buff
}
