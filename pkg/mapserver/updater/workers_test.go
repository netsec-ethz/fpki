package updater

import (
	"context"
	"math"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
	pip "github.com/netsec-ethz/fpki/pkg/pipeline"
	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/netsec-ethz/fpki/pkg/tests/noopdb"
	"github.com/netsec-ethz/fpki/pkg/tests/random"
	"github.com/netsec-ethz/fpki/pkg/util/debug"
	"github.com/stretchr/testify/require"
)

func TestDomainBatcherNotBlocking(t *testing.T) {
	defer pip.PrintAllDebugLines()

	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	// DB with no operations.
	conn := &noopdb.Conn{}

	// Create mock certificates.
	N := 4
	certs := toCertificates(random.BuildTestRandomCertTree(t, random.RandomLeafNames(t, N)...))
	domains := extractDomains(certs)
	domains = domains[:N]
	t.Logf("# domains: %d", len(domains))

	const batchSize = 2
	manager, err := NewManager(1, conn, batchSize, math.MaxUint64, nil, time.Hour, nil)
	require.NoError(t, err)

	// Create a domain batcher stage.
	worker := newDomainBatcher(0, manager, 1)
	worker.Ctx = ctx

	// Mock a source. Don't run it yet.
	sendDomainsCh := make(chan struct{})
	sourceIsDone := make(chan struct{})
	sending := atomic.Uint32{}
	go func() {
		for j := 0; j < 2; j++ {
			<-sendDomainsCh
			for i := 0; i < manager.MultiInsertSize; i++ {
				worker.IncomingChs[0] <- domains[j+i]
				t.Log("mock source sent domain")
				sending.Add(1)
			}
		}

		close(worker.IncomingChs[0])
		t.Log("mock source done")
		sourceIsDone <- struct{}{}
	}()

	// Mock a sink. Its processing function blocks.
	sinkErrCh := make(chan error)
	sinkIsProcessing := make(chan struct{})
	blockSinkProcessing := make(chan struct{})
	worker.OutgoingChs[0] = make(chan domainBatch)
	go func() {
		t.Logf("mock sink: reading all outputs from %s", debug.Chan2str(worker.OutgoingChs[0]))
		for range worker.OutgoingChs[0] {
			// Indicate we are processing.
			t.Log("mock sink: processing")
			sinkIsProcessing <- struct{}{}

			// Wait until the test controller unblocks.
			t.Log("mock sink: waiting ...")
			<-blockSinkProcessing
			t.Log("mock sink: finished processing")
		}
		close(sinkErrCh)
		close(sinkIsProcessing)
		t.Log("mock sink: done")
	}()

	// Resume stage but not yet source.
	worker.Prepare(ctx)
	worker.NextErrChs[0] = sinkErrCh
	worker.Resume(ctx)

	var last uint32
	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()

		// Wait for completion.
		err = <-worker.ErrCh
		require.NoError(t, err)
		t.Log("controller: worker exited")
	}()
	go func() {
		defer wg.Done()

		// Initial batch.
		sendDomainsCh <- struct{}{}

		// Wait for the first batch to arrive.
		<-sinkIsProcessing
		last = sending.Load()

		// Signal to send and create another batch.
		sendDomainsCh <- struct{}{}

		// Processing is still stopped. Wait for the source to be done.
		<-sourceIsDone

		// Unblock processing of the first batch.
		blockSinkProcessing <- struct{}{}
		// Wait for the second batch to arrive.
		<-sinkIsProcessing
		// Unblock processing of the second and last batch.
		blockSinkProcessing <- struct{}{}
	}()

	tests.TestOrTimeout(t, tests.WithContext(ctx), func(t tests.T) {
		// Wait for both goroutines.
		wg.Wait()
	})

	// Check that the current sent domain count is larger.
	t.Logf("previous: %d, current: %d", last, sending.Load())
	require.Greater(t, sending.Load(), last)

	// Housekeeping.
	close(blockSinkProcessing)
}

func TestDomainBatcherAllocationOverhead(t *testing.T) {
	defer pip.PrintAllDebugLines()

	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	// DB with no operations.
	conn := &noopdb.Conn{}

	// Create mock certificates.
	N := 100
	certs := toCertificates(random.BuildTestRandomCertTree(t, random.RandomLeafNames(t, N)...))
	domains := extractDomains(certs)

	manager, err := NewManager(1, conn, 10, math.MaxUint64, nil, time.Hour, nil)
	require.NoError(t, err)

	// Create a domain batcher stage.
	worker := newDomainBatcher(0, manager, 1)
	worker.Ctx = ctx

	// Modify output function for the purposes of not using the allocating concurrent one:
	pip.TestOnlyPurposeSetOutputFunction(
		t,
		worker.Stage,
		pip.OutputSequentialCyclesAllowed,
	)

	// Mock a source. Don't run it yet.
	sendDomainsCh := make(chan struct{})
	go func() {

		// Wait for the test to start.
		<-sendDomainsCh

		for _, d := range domains {
			worker.IncomingChs[0] <- d
		}
		close(worker.IncomingChs[0])
	}()

	// Mock a sink.
	sinkErrCh := make(chan error)
	worker.OutgoingChs[0] = make(chan domainBatch)
	go func() {
		t.Logf("reading all outputs from %s", debug.Chan2str(worker.OutgoingChs[0]))
		for range worker.OutgoingChs[0] {
		}
		close(sinkErrCh)
	}()

	// Resume stage but not yet source.
	worker.Prepare(ctx)
	worker.NextErrChs[0] = sinkErrCh
	worker.Resume(ctx)

	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	allocs := tests.AllocsPerRun(func(tests.B) {
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

func extractDomains(certs []Certificate) []DirtyDomain {
	domains := make([]DirtyDomain, 0, len(certs))
	for _, c := range certs {
		// Iff the certificate is a leaf certificate it will have a non-nil names slice: insert
		// one entry per name.
		for _, name := range c.Names {
			domain := DirtyDomain{
				DomainID: common.SHA256Hash32Bytes([]byte(name)),
				CertID:   c.CertID,
				Name:     name,
			}
			domains = append(domains, domain)
		}
	}
	return domains
}
