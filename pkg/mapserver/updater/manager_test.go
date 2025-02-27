package updater

import (
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/stretchr/testify/require"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	pip "github.com/netsec-ethz/fpki/pkg/pipeline"
	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/netsec-ethz/fpki/pkg/tests/noopdb"
	"github.com/netsec-ethz/fpki/pkg/tests/random"
	"github.com/netsec-ethz/fpki/pkg/tests/testdb"
	"github.com/netsec-ethz/fpki/pkg/util/debug"
)

func TestManagerStart(t *testing.T) {
	defer pip.PrintAllDebugLines()

	testCases := map[string]struct {
		NLeafDomains     int
		certGenerator    func(tests.T, ...string) []Certificate
		expectedNCerts   int
		expectedNDomains int
		NWorkers         int
		MultiInsertSize  int
	}{
		"lonely": {
			NLeafDomains:     1,
			certGenerator:    sameAncestryHierarchy,
			expectedNCerts:   2 + 1, // c0, c1 and leaf.
			expectedNDomains: 2 + 1,
			NWorkers:         1,
			MultiInsertSize:  1,
		},
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

			defer pip.PrintAllDebugLines()

			ctx, cancelF := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancelF()

			t.Logf("%s starting", time.Now().Format(time.StampMicro))

			// Configure a test DB.
			config, removeF := testdb.ConfigureTestDB(t)
			defer removeF()
			t.Logf("%s DB configured", time.Now().Format(time.StampMicro))

			// Connect to the DB.
			t.Logf("%s connecting to DB", time.Now().Format(time.StampMicro))
			conn := testdb.Connect(t, config)
			defer conn.Close()
			t.Logf("%s connected to DB", time.Now().Format(time.StampMicro))

			manager, err := NewManager(
				tc.NWorkers,
				conn,
				tc.MultiInsertSize,
				math.MaxUint64,
				nil,
				time.Hour,
				nil,
			)
			require.NoError(t, err)

			certs := tc.certGenerator(t, mockLeaves(tc.NLeafDomains)...)
			t.Logf("Manager: %p number of certs: %d", manager, len(certs))
			// Log their IDs, for debugging purposes.
			IDs := make([]string, len(certs))
			for i, c := range certs {
				IDs[i] = hex.EncodeToString(c.CertID[:])
			}
			t.Logf("IDs:\n%s", strings.Join(IDs, "\n"))

			tests.TestOrTimeout(t, tests.WithContext(ctx), func(t tests.T) {
				manager.Resume(ctx)
				pip.DebugPrintf("Pipeline resumed\n")
				t.Logf("%s Pipeline resumed", time.Now().Format(time.StampMicro))

				processCertificates(t, manager, certs)
				manager.Stop()
				err := manager.Wait(ctx)
				require.NoError(t, err)
			})
			verifyDB(ctx, t, conn, tc.expectedNCerts, tc.expectedNDomains)
		})
	}
}

func TestManagerResume(t *testing.T) {
	defer pip.PrintAllDebugLines()

	testCases := map[string]struct {
		NLeafDomains    int
		NWorkers        int
		MultiInsertSize int
		NStages         int
	}{
		"lonely": {
			NLeafDomains:    1,
			NWorkers:        1,
			MultiInsertSize: 1,
			NStages:         1,
		},
		"two": {
			NLeafDomains:    11,
			NWorkers:        2,
			MultiInsertSize: 10,
			NStages:         2,
		},
		"seven": {
			NLeafDomains:    121,
			NWorkers:        4,
			MultiInsertSize: 50,
			NStages:         7,
		},
		"toomany_stages": {
			NLeafDomains:    1,
			NWorkers:        1,
			MultiInsertSize: 1,
			NStages:         5,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctx, cancelF := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancelF()

			// Configure a test DB.
			config, removeF := testdb.ConfigureTestDB(t)
			defer removeF()

			// Connect to the DB.
			conn := testdb.Connect(t, config)
			defer conn.Close()

			manager, err := NewManager(
				tc.NWorkers,
				conn,
				tc.MultiInsertSize,
				math.MaxUint64,
				nil,
				time.Hour,
				nil,
			)
			require.NoError(t, err)

			N := tc.NLeafDomains
			certs := sameAncestryHierarchy(t, mockLeaves(N)...)
			t.Logf("Manager: %p number of certs: %d", manager, len(certs))
			// Log their IDs, for debugging purposes.
			IDs := make([]string, len(certs))
			for i, c := range certs {
				IDs[i] = hex.EncodeToString(c.CertID[:])
			}
			t.Logf("IDs:\n%s", strings.Join(IDs, "\n"))

			stageSize := len(certs) / tc.NStages
			for stage := 0; stage < tc.NStages; stage++ {
				tests.TestOrTimeout(t, tests.WithContext(ctx), func(t tests.T) {
					t.Logf("Starting stage %d/%d", stage, tc.NStages)
					S := stage * stageSize
					E := S + stageSize
					if stage == tc.NStages-1 {
						E = len(certs)
					}
					stagedCerts := certs[S:E]

					manager.Resume(ctx)
					processCertificates(t, manager, stagedCerts)
					manager.Stop()
					err := manager.Wait(ctx)
					require.NoError(t, err)
				})
			}

			t.Log("All stages finished")
			verifyDB(ctx, t, conn, tc.NLeafDomains+2, tc.NLeafDomains+2)
		})
	}
}

func TestMinimalAllocsManager(t *testing.T) {
	defer pip.PrintAllDebugLines()

	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	// DB with no operations.
	conn := &noopdb.Conn{}

	// Create mock certificates.
	N := 100
	certs := toCertificates(random.BuildTestRandomCertTree(t, random.RandomLeafNames(t, N)...))
	// Prepare the manager and worker for the test.
	manager := createManagerWithOutputFunction(t, conn, 2, pip.OutputSequentialCyclesAllowed)

	// Now check the number of allocations happening inside the manager, once it runs.
	manager.Resume(ctx)
	processCertificates(t, manager, certs)
	time.Sleep(100 * time.Millisecond)
	tests.TestOrTimeout(t, tests.WithContext(ctx), func(t tests.T) {
		var err error
		allocsPerRun := tests.AllocsPerRun(func() {
			manager.Stop()
			err = manager.Wait(ctx)
		})
		require.NoError(t, err)

		t.Logf("allocations = %d", allocsPerRun)
		// The test is noisy, we sometimes get 2 allocations, etc.
		require.LessOrEqual(t, allocsPerRun, N/10)
	})
}

func diffAncestryHierarchy(t tests.T, leaves ...string) []Certificate {
	var payloads []ctx509.Certificate
	var IDs []common.SHA256Output
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

func sameAncestryHierarchy(t tests.T, leaves ...string) []Certificate {
	return toCertificates(random.BuildTestRandomCertTree(t, leaves...))
}

func generatorCertCloner(
	generator func(tests.T, ...string) []Certificate,
	multiplier int,
) func(tests.T, ...string) []Certificate {

	return func(t tests.T, leaves ...string) []Certificate {
		return cloneCertSlice(generator(t, leaves...), multiplier)
	}
}

// cloneCertSlice clones certs `multiplier` times. If multiplier is 1, no cloning is done.
func cloneCertSlice(certs []Certificate, multiplier int) []Certificate {
	// Duplicate all entries.
	duplicated := certs
	for i := 1; i < multiplier; i++ {
		for _, pC := range certs {
			payload := pC.Cert
			id := pC.CertID
			pParentID := pC.ParentID
			if pParentID != nil {
				parent := *pParentID
				pParentID = &parent
			}
			names := append(pC.Names[:0:0], pC.Names...)

			c := Certificate{
				Cert:     payload,
				CertID:   id,
				ParentID: pParentID,
				Names:    names,
			}
			duplicated = append(duplicated, c)
		}
	}
	return duplicated
}

func toCertificates(
	payloads []ctx509.Certificate,
	ids []common.SHA256Output,
	parentIDs []*common.SHA256Output,
	names [][]string,
) []Certificate {

	certs := make([]Certificate, 0, len(payloads))
	for i := 0; i < len(payloads); i++ {
		c := Certificate{
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

func processCertificates(t tests.T, m *Manager, certs []Certificate) {
	t.Logf("sending %d certs to incoming chan: %s", len(certs), debug.Chan2str(m.IncomingCertChan))
	for _, c := range certs {
		m.IncomingCertChan <- c
		t.Logf("sent another certificate")
	}
}

func verifyDB(ctx context.Context, t tests.T, conn db.Conn,
	ncerts int, ndomains int,
) {
	t.Helper()

	checkTable := func(field string, table string, n int) {
		t.Helper()
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
	checkTable("cert_id", "domain_certs", ndomains)
}

// createManagerWithOutputFunction creates a manager, and modifies the output functions of all the
// stages in the manager for the purposes of not using the allocating concurrent one.
func createManagerWithOutputFunction(
	t *testing.T,
	conn db.Conn,
	workerCount int,
	outType pip.DebugPurposesOnlyOutputType,
) *Manager {

	manager, err := NewManager(workerCount, conn, 10, math.MaxUint64, nil, time.Hour, nil)
	require.NoError(t, err)

	stages := manager.Pipeline.Stages

	// A. Source:
	pip.TestOnlyPurposeSetOutputFunction(
		t,
		pip.SourceAsStage(stages[0].(*pip.Source[Certificate])),
		outType,
	)

	// B. Cert batchers:
	for _, s := range findStagesByType[pip.Stage[Certificate, CertBatch]](t, stages) {
		pip.TestOnlyPurposeSetOutputFunction(t, s, outType)
	}

	// C. Domain extractors:
	for _, s := range findStagesByType[pip.Stage[Certificate, DirtyDomain]](t, stages) {
		pip.TestOnlyPurposeSetOutputFunction(t, s, outType)
	}

	// D. Cert csv creators:
	for _, s := range findStagesByType[pip.Stage[CertBatch, string]](t, stages) {
		pip.TestOnlyPurposeSetOutputFunction(t, s, outType)
	}

	// E. Cert csv inserters:
	for _, s := range findStagesByType[pip.Stage[string, string]](t, stages) {
		pip.TestOnlyPurposeSetOutputFunction(t, s, outType)
	}

	// F. Cert csv removers:
	for _, s := range findStagesByType[pip.Sink[string]](t, stages) {
		pip.TestOnlyPurposeSetOutputFunction(t, s.Stage, outType)
	}

	// G. Domain batchers:
	for _, s := range findStagesByType[pip.Stage[DirtyDomain, domainBatch]](t, stages) {
		pip.TestOnlyPurposeSetOutputFunction(t, s, outType)
	}

	// H. Domain csv creators:
	for _, s := range findStagesByType[pip.Stage[domainBatch, domainsCsvFilenames]](t, stages) {
		pip.TestOnlyPurposeSetOutputFunction(t, s, outType)
	}

	// I. Domain csv inserters:
	for _, s := range findStagesByType[pip.Stage[domainsCsvFilenames, domainsCsvFilenames]](t, stages) {
		pip.TestOnlyPurposeSetOutputFunction(t, s, outType)
	}

	// J. Domain csv removers, sinks:
	for _, s := range findStagesByType[pip.Sink[domainsCsvFilenames]](t, stages) {
		pip.TestOnlyPurposeSetOutputFunction(t, s.Stage, outType)
	}

	return manager
}

func findStagesByType[T any, PT interface{ *T }](t tests.T, stages []pip.StageLike) []PT {
	found := make([]PT, 0)
	for _, s := range stages {
		if s, ok := s.(PT); ok {
			found = append(found, s)
		}
	}
	require.Greaterf(t, len(found), 0, "the type '%T' was not found", *new(T))
	return found
}
