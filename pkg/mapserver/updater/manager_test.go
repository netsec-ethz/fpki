package updater_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	"github.com/netsec-ethz/fpki/pkg/tests/random"
	"github.com/netsec-ethz/fpki/pkg/tests/testdb"
)

func TestManagerStart(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelF()

	// Configure a test DB.
	config, removeF := testdb.ConfigureTestDB(t)
	defer removeF()

	// Connect to the DB.
	conn := testdb.Connect(t, config)
	defer conn.Close()

	certs := mockCertificates(t, 2)

	manager := updater.NewManager(ctx, 2, conn, 10, time.Second, nil)
	manager.ProcessCertificates(certs)
	manager.Wait()

	// Verify they are in the DB.
	row := conn.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM certs")
	require.NoError(t, row.Err())
	count := 0
	err := row.Scan(&count)
	require.NoError(t, err)
	require.Equal(t, 7, count)
}

func mockCertificates(t *testing.T, numberOfLeaves int) []*updater.Certificate {
	leafs := make([]string, numberOfLeaves)
	for i := 0; i < numberOfLeaves; i++ {
		leafs[i] = fmt.Sprintf("domain-%3d.com", i)
	}

	certs := make([]*updater.Certificate, 0)
	for _, leaf := range leafs {
		payloads, IDs, parentIDs, names := random.BuildTestRandomCertHierarchy(t, leaf)
		for i := 0; i < len(payloads); i++ {
			c := &updater.Certificate{
				CertID:   IDs[i],
				Cert:     payloads[i],
				ParentID: parentIDs[i],
				Names:    names[i],
			}
			certs = append(certs, c)
		}
	}
	return certs
}
