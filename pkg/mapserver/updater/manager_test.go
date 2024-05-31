package updater_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/stretchr/testify/require"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/netsec-ethz/fpki/pkg/tests/random"
	"github.com/netsec-ethz/fpki/pkg/tests/testdb"
)

func TestManagerStart(t *testing.T) {
	testCases := map[string]struct {
		NLeafDomains     int
		certGenerator    func(tests.T, ...string) []*updater.Certificate
		expectedNCerts   int
		expectedNDomains int
		NWorkers         int
		MultiInsertSize  int
	}{
		"different_ancestors": {
			NLeafDomains:     8,
			certGenerator:    diffAncestryHierarchy,
			expectedNCerts:   4 * 8,
			expectedNDomains: 2 + 8,
			NWorkers:         4,
			MultiInsertSize:  16,
		},
		"different_mult2": {
			// Will duplicate certs by x2.
			NLeafDomains:     4,
			certGenerator:    generatorCertCloner(diffAncestryHierarchy, 2),
			expectedNCerts:   4 * 4,
			expectedNDomains: 2 + 4,
			NWorkers:         2,
			MultiInsertSize:  1,
		},
		"same_ancestry": {
			NLeafDomains:     4,
			certGenerator:    sameAncestryHierarchy,
			expectedNCerts:   2 + 4, // c0, c1 and leaves.
			expectedNDomains: 2 + 4,
			NWorkers:         4,
			MultiInsertSize:  1,
		},
		"same_mult3": {
			// Will replicate certs by x3.
			NLeafDomains:     4,
			certGenerator:    generatorCertCloner(sameAncestryHierarchy, 3),
			expectedNCerts:   2 + 4,
			expectedNDomains: 2 + 4,
			NWorkers:         4,
			MultiInsertSize:  2,
		},

		// All of the following test cases will be using the sameAncestry generator.

		"1000leafs_4workers_1024multi": {
			NLeafDomains:     1000,
			certGenerator:    sameAncestryHierarchy,
			expectedNCerts:   2 + 1000,
			expectedNDomains: 2 + 1000,
			NWorkers:         4,
			MultiInsertSize:  1024,
		},
		"100leafs_2workers_10multi": {
			NLeafDomains:     100,
			certGenerator:    sameAncestryHierarchy,
			expectedNCerts:   2 + 100,
			expectedNDomains: 2 + 100,
			NWorkers:         2,
			MultiInsertSize:  10,
		},
		"3leafs_4workers_10multi": {
			NLeafDomains:     3,
			certGenerator:    sameAncestryHierarchy,
			expectedNCerts:   2 + 3,
			expectedNDomains: 2 + 3,
			NWorkers:         4,
			MultiInsertSize:  10,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancelF()

			// Configure a test DB.
			config, removeF := testdb.ConfigureTestDB(t)
			defer removeF()

			// Connect to the DB.
			conn := testdb.Connect(t, config)
			defer conn.Close()

			manager := updater.NewManager(ctx, tc.NWorkers, conn, tc.MultiInsertSize, time.Second, nil)

			certs := tc.certGenerator(t, mockLeaves(tc.NLeafDomains)...)
			t.Logf("Manager: %p number of certs: %d", manager, len(certs))
			// Log their IDs, for debugging purposes.
			IDs := make([]string, len(certs))
			for i, c := range certs {
				IDs[i] = hex.EncodeToString(c.CertID[:])
			}
			t.Logf("IDs:\n%s", strings.Join(IDs, "\n"))

			processCertificates(manager, certs)
			manager.Stop()
			err = manager.Wait()
			require.NoError(t, err)
			verifyDB(ctx, t, conn, tc.expectedNCerts, tc.expectedNDomains)
		})
	}
}

func diffAncestryHierarchy(t tests.T, leaves ...string) []*updater.Certificate {
	var payloads []*ctx509.Certificate
	var IDs []*common.SHA256Output
	var parentIDs []*common.SHA256Output
	var names [][]string

	for _, leaf := range leaves {
		payloads2, IDs2, parentIDs2, names2 := random.BuildTestRandomCertHierarchy(t, leaf)

		payloads = append(payloads, payloads2...)
		IDs = append(IDs, IDs2...)
		parentIDs = append(parentIDs, parentIDs2...)
		names = append(names, names2...)
	}
	return toCertificates(payloads, IDs, parentIDs, names)
}

func sameAncestryHierarchy(t tests.T, leaves ...string) []*updater.Certificate {
	return toCertificates(random.BuildTestRandomCertTree(t, leaves...))
}

func generatorCertCloner(
	generator func(tests.T, ...string) []*updater.Certificate,
	multiplier int,
) func(tests.T, ...string) []*updater.Certificate {

	return func(t tests.T, leaves ...string) []*updater.Certificate {
		return cloneCertSlice(generator(t, leaves...), multiplier)
	}
}

// cloneCertSlice clones certs `multiplier` times. If multiplier is 1, no cloning is done.
func cloneCertSlice(certs []*updater.Certificate, multiplier int) []*updater.Certificate {
	// Duplicate all entries.
	duplicated := certs
	for i := 1; i < multiplier; i++ {
		for _, pC := range certs {
			payload := *pC.Cert
			id := *pC.CertID
			pParentID := pC.ParentID
			if pParentID != nil {
				parent := *pParentID
				pParentID = &parent
			}
			names := append(pC.Names[:0:0], pC.Names...)

			c := updater.Certificate{
				Cert:     &payload,
				CertID:   &id,
				ParentID: pParentID,
				Names:    names,
			}
			duplicated = append(duplicated, &c)
		}
	}
	return duplicated
}

func toCertificates(
	payloads []*ctx509.Certificate,
	ids,
	parentIDs []*common.SHA256Output,
	names [][]string,
) []*updater.Certificate {

	certs := make([]*updater.Certificate, 0)
	for i := 0; i < len(payloads); i++ {
		c := &updater.Certificate{
			CertID:   ids[i],
			Cert:     payloads[i],
			ParentID: parentIDs[i],
			Names:    names[i],
		}
		certs = append(certs, c)
	}

	return certs
}

func mockLeaves(numberOfLeaves int) []string {
	leaves := make([]string, numberOfLeaves)
	for i := 0; i < numberOfLeaves; i++ {
		leaves[i] = fmt.Sprintf("domain-%03d.com", i)
	}
	return leaves
}

func processCertificates(m *updater.Manager, certs []*updater.Certificate) {
	for _, c := range certs {
		m.IncomingCertChan <- c
	}
}

func verifyDB(ctx context.Context, t tests.T, conn db.Conn,
	ncerts int, ndomains int,
) {

	t.Helper()

	checkTable := func(field string, table string, n int) {
		rows, err := conn.DB().QueryContext(ctx,
			fmt.Sprintf("SELECT %s FROM %s", field, table))
		require.NoError(t, err)
		require.NoError(t, rows.Err())

		ids := make([]string, 0)
		for rows.Next() {
			var id []byte
			err := rows.Scan(&id)
			require.NoError(t, err)
			ids = append(ids, hex.EncodeToString(id))
		}
		str := ""
		if n != len(ids) {
			str = fmt.Sprintf("failure at %s\tExisting IDs in table:\n%s",
				table, strings.Join(ids, "\n"))
		}
		require.Equal(t, n, len(ids), str)
	}

	// Check number of certificates.
	checkTable("cert_id", "certs", ncerts)

	// Check number of domains.
	checkTable("domain_id", "domains", ndomains)

	// Check number of dirty domains.
	checkTable("domain_id", "dirty", ndomains)

	// Check number of cert-domains.
	checkTable("cert_id", "domain_certs", ncerts)
}
