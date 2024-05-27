package updater_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/rand"
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
		"deleteme1": {
			// Will duplicate certs
			NLeafDomains:     4,
			certGenerator:    diffAncestryHierarchyDeletemeMult(2), // duplicates entries
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
			// deleteme debug notes:
			/*
				1. With this test case I sometimes get a deadlock in mysql.


				2. And also a dead lock in the process, as the manager is not finishing.
					Correction: the dead lock in the manager is due to errors being thrown (deadlock in DB).
					Let's fix this first.
					FIXED

				3. Playing with transactions, sometimes I get less entries in certs or domains than expected.
					It seems that the last SQL statement is, for some reason, not really committed.
					The call to COMMIT does not fail, though.
					Actually, one SQL statement seems not to commit, not always the last one, although most
					frequently it is the last one.

					It fails regardless of autocommit or the transaction isolation level,
					at least using insert ignore. [3min to fail]

					So far it seems to work with:
					- autocommit=0
					- no BEGIN or START TRANSACTION
					- COMMIT at the end of inserting in dirty
					||||||||||||||||||||||||||||||||||||
					Nope, it also failed [9min to fail]
			*/
		},
		"deleteme2": {
			// Will duplicate certs
			NLeafDomains:     2,
			certGenerator:    diffAncestryHierarchyDeletemeMult(16), // x16 the original certs
			expectedNCerts:   4 * 2,
			expectedNDomains: 2 + 2,
			NWorkers:         2,
			MultiInsertSize:  2,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			// t.Parallel()

			// ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Second)
			ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Hour) // deleteme
			defer cancelF()

			// Configure a test DB.
			// tt := NewTT(t)
			// t.Logf("Running with special name: %s", tt.Name())
			// config, removeF := testdb.ConfigureTestDB(tt)
			config, removeF := testdb.ConfigureTestDB(t)
			defer removeF()
			// _ = removeF // deleteme

			// Connect to the DB.
			conn := testdb.Connect(t, config)
			defer conn.Close()

			// deleteme:
			// str := "SELECT 'deleteme';"
			// str := "SET autocommit=0;"
			str := "SET autocommit=1;"
			_, err := conn.DB().ExecContext(ctx, str)
			require.NoError(t, err)

			// str = "SET GLOBAL innodb_lock_wait_timeout = 1;" // trying to catch bugs
			// _, err = conn.DB().ExecContext(ctx, str)
			// require.NoError(t, err)

			str = "SET GLOBAL TRANSACTION ISOLATION LEVEL REPEATABLE READ"
			// str = "SET GLOBAL TRANSACTION ISOLATION LEVEL READ UNCOMMITTED"
			_, err = conn.DB().ExecContext(ctx, str)
			require.NoError(t, err)

			certs := tc.certGenerator(t, mockLeaves(tc.NLeafDomains)...)

			manager := updater.NewManager(ctx, tc.NWorkers, conn, tc.MultiInsertSize, time.Second, nil)

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

// deletemeDuplicateCerts clones certs `multiplier` times. If multiplier is 1, no cloning is done.
func deletemeDuplicateCerts(certs []*updater.Certificate, multiplier int) []*updater.Certificate {
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

func diffAncestryHierarchyDeletemeMult(multiplier int) func(tests.T, ...string) []*updater.Certificate {
	return func(t tests.T, leaves ...string) []*updater.Certificate {
		return deletemeDuplicateCerts(diffAncestryHierarchy(t, leaves...), multiplier)
	}
}

func sameAncestryHierarchy(t tests.T, leaves ...string) []*updater.Certificate {
	return toCertificates(random.BuildTestRandomCertTree(t, leaves...))
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

	// // Check number of certificates.
	// checkTable("cert_id", "certs", ncerts)

	// Check number of domains.
	checkTable("domain_id", "domains", ndomains)

	// Check number of dirty domains.
	checkTable("domain_id", "dirty", ndomains)

	// // Check number of cert-domains.
	// checkTable("cert_id", "domain_certs", ncerts)
}

type TT struct {
	*testing.T
	rn int
}

func NewTT(t *testing.T) *TT {
	return &TT{
		T:  t,
		rn: rand.Intn(1000000),
	}
}

func (t *TT) Name() string {
	return fmt.Sprintf("%s_%06d", t.T.Name(), t.rn)
}
