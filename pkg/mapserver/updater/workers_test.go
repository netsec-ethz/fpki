package updater_test

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	pip "github.com/netsec-ethz/fpki/pkg/pipeline"
	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/netsec-ethz/fpki/pkg/tests/noopdb"
	"github.com/netsec-ethz/fpki/pkg/tests/random"
	"github.com/netsec-ethz/fpki/pkg/util/debug"
	"github.com/stretchr/testify/require"
)

// TestAllocsCertWorkerProcessBundle checks that the calls to deduplicate elements in CertWorker
// do not need special memory allocations, due to the static fields present in the struct.
func TestAllocsCertWorkerProcessBundle(t *testing.T) {
	defer pip.PrintAllDebugLines()

	// Cert worker use of allocation calls.
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	// DB with no operation.
	conn := &noopdb.Conn{}

	// Create mock certificates.
	N := 10
	certs := toCertificates(random.BuildTestRandomCertTree(t, random.RandomLeafNames(t, N)...))

	// Prepare the manager and worker for the test.
	manager, err := updater.NewManager(ctx, 1, conn, 1000, 1, nil)
	require.NoError(t, err)

	// The only interesting stage for this test is the one with the certificate worker.
	// For that purpose, we mock the source and sink.
	worker := updater.NewCertWorker(ctx, 0, manager, conn, 1)

	// Bundle the mock data.
	worker.Certs = certs

	// Measure the test function.
	worker.Certs = certs
	allocsPerRun := tests.AllocsPerRun(func() {
		worker.ProcessBundle()
		conn.UpdateCerts(
			ctx,
			worker.CacheIds(),
			worker.CacheParents(),
			worker.CacheExpirations(),
			worker.CachePayloads(),
		)
	})

	// We should have 0 new allocations.
	t.Logf("%d allocations", allocsPerRun)
	require.Equal(t, 0, allocsPerRun)
}

// TestCertWorkerOverhead checks the extra amount of memory that the certificate worker uses,
// other than that used by the main processing function processBundle.
func TestCertWorkerAllocationsOverhead(t *testing.T) {
	defer pip.PrintAllDebugLines()

	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	// DB with no operations.
	conn := &noopdb.Conn{}

	// Create mock certificates.
	N := 100
	certs := toCertificates(random.BuildTestRandomCertTree(t, random.RandomLeafNames(t, N)...))

	manager, err := updater.NewManager(ctx, 1, conn, 10, 1, nil)
	require.NoError(t, err)

	// Create a cert worker stage. Input channel of Certificate, output of DirtyDomain.
	worker := updater.NewCertWorker(ctx, 0, manager, conn, 1)

	// Modify output function for the purposes of not using the allocating concurrent one:
	pip.TestOnlyPurposeSetOutputFunction(
		t,
		worker.Stage,
		pip.OutputSequentialCyclesAllowed,
	)

	// Mock a sink.
	sinkErrCh := make(chan error)
	worker.OutgoingChs[0] = make(chan updater.DirtyDomain)
	go func() {
		t.Logf("reading all outputs from %s", debug.Chan2str(worker.OutgoingChs[0]))
		for range worker.OutgoingChs[0] {
		}
		close(sinkErrCh)
	}()

	// Mock a source. Don't run it yet.
	sendCertsCh := make(chan struct{})
	go func() {
		<-sendCertsCh
		for _, cert := range certs {
			worker.IncomingChs[0] <- cert
		}
		close(worker.IncomingChs[0])
	}()

	// Resume stage but not yet source.
	worker.Prepare(ctx)
	worker.NextErrChs[0] = sinkErrCh
	worker.Resume(ctx)

	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	tests.TestOrTimeout(t, tests.WithContext(ctx), func(t tests.T) {
		allocs := tests.AllocsPerRun(func() {
			// All is set up. Start processing and measure allocations.
			sendCertsCh <- struct{}{}
			// Wait for completion.
			err = <-worker.ErrCh
		})
		require.NoError(t, err)
		t.Logf("allocs = %d", allocs)
		// The test is flaky: sometimes we get 0 allocations, sometimes 1 or even more.
		require.LessOrEqual(t, allocs, N/10)
	})
}

// TestAllocsDomainWorkerProcessBundle checks that the calls to deduplicate elements in DomainWorker
// do not need special memory allocations, due to the static fields present in the struct.
func TestAllocsDomainWorkerProcessBundle(t *testing.T) {
	defer pip.PrintAllDebugLines()

	// Domain worker use of allocation calls.

	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	// DB with no operations.
	conn := &noopdb.Conn{}

	// Create mock certificates.
	N := 10
	certs := toCertificates(random.BuildTestRandomCertTree(t, random.RandomLeafNames(t, N)...))

	// Prepare the manager and worker for the test.
	manager, err := updater.NewManager(ctx, 1, conn, 1000, 1, nil)
	require.NoError(t, err)
	worker := updater.NewDomainWorker(ctx, 0, manager, conn, 1)

	// Bundle the mock data.
	bundle := extractDomains(certs)
	bundle = bundle[:min(len(bundle), manager.MultiInsertSize)] // limit to the size of the bundle
	worker.Domains = bundle

	// Measure the test function.
	allocsPerRun := tests.AllocsPerRun(func() {
		worker.ProcessBundle()
	})

	// We should have 0 new allocations.
	t.Logf("%d allocations", allocsPerRun)
	require.Equal(t, 0, allocsPerRun)
}

// TestDomainWorkerOverhead checks the extra amount of memory that the domain worker uses,
// other than that used by the main processing function processBundle.
func TestDomainWorkerAllocationsOverhead(t *testing.T) {
	defer pip.PrintAllDebugLines()

	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	// DB with no operations.
	conn := &noopdb.Conn{}

	// Create mock certificates.
	N := 100
	certs := toCertificates(random.BuildTestRandomCertTree(t, random.RandomLeafNames(t, N)...))
	domains := extractDomains(certs)

	manager, err := updater.NewManager(ctx, 1, conn, 10, 1, nil)
	require.NoError(t, err)

	// Create a cert worker stage. Input channel of Certificate, output of DirtyDomain.
	worker := updater.NewDomainWorker(ctx, 0, manager, conn, 1)

	// Modify output function for the purposes of not using the allocating concurrent one:
	pip.TestOnlyPurposeSetOutputFunction(
		t,
		worker.Stage,
		pip.OutputSequentialCyclesAllowed,
	)

	// Mock a source. Don't run it yet.
	sendDomainsCh := make(chan struct{})
	go func() {
		<-sendDomainsCh
		for _, domain := range domains {
			worker.IncomingChs[0] <- domain
		}
		close(worker.IncomingChs[0])
	}()

	// Resume stage but not yet source.
	worker.Prepare(ctx)
	worker.Resume(ctx)

	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	allocs := tests.AllocsPerRun(func() {
		// All is set up. Start processing and measure allocations.
		sendDomainsCh <- struct{}{}
		// Wait for completion.
		err = <-worker.ErrCh
	})
	require.NoError(t, err)
	t.Logf("allocs = %d", allocs)
	// The test is flaky: sometimes we get 0 allocations, sometimes 1 or even more.
	require.LessOrEqual(t, allocs, N/10)
}

func extractDomains(certs []updater.Certificate) []updater.DirtyDomain {
	domains := make([]updater.DirtyDomain, 0, len(certs))
	for _, c := range certs {
		// Iff the certificate is a leaf certificate it will have a non-nil names slice: insert
		// one entry per name.
		for _, name := range c.Names {
			domain := updater.DirtyDomain{
				DomainID: common.SHA256Hash32Bytes([]byte(name)),
				CertID:   c.CertID,
				Name:     name,
			}
			domains = append(domains, domain)
		}
	}
	return domains
}
