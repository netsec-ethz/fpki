package main

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db/mysql"
)

// TestDistributeBySkewNo checks that the "no" skew mode stays effectively uniform, modulo
// integer rounding, and still allocates the full requested workload.
func TestDistributeBySkewNo(t *testing.T) {
	got := distributeBySkew(20_480, "no")
	total := 0
	for _, count := range got {
		total += count
	}
	if total != 20_480 {
		t.Fatalf("wrong total: got %d", total)
	}
	minCount, maxCount := got[0], got[0]
	for _, count := range got[1:] {
		if count < minCount {
			minCount = count
		}
		if count > maxCount {
			maxCount = count
		}
	}
	if maxCount-minCount > 1 {
		t.Fatalf("expected nearly uniform distribution, min=%d max=%d", minCount, maxCount)
	}
}

// TestDistributeBySkewLarge checks that the "large" skew mode really shifts more work into the
// heavier half of the partitions.
func TestDistributeBySkewLarge(t *testing.T) {
	got := distributeBySkew(32_000, "large")
	lowHalf := 0
	highHalf := 0
	for i := 0; i < partitionCount/2; i++ {
		lowHalf += got[i]
	}
	for i := partitionCount / 2; i < partitionCount; i++ {
		highHalf += got[i]
	}
	if lowHalf <= highHalf {
		t.Fatalf("expected lower-weight half to receive less work, got low=%d high=%d", lowHalf, highHalf)
	}
}

// TestMixedDomainsForBalance checks the two edge cases of the policy/certificate balance logic:
// no policies at 0%, and all active domains mixed at the 75% cap.
func TestMixedDomainsForBalance(t *testing.T) {
	if got := mixedDomainsForBalance(100, 0); got != 0 {
		t.Fatalf("got %d, want 0", got)
	}
	if got := mixedDomainsForBalance(100, 75); got != 100 {
		t.Fatalf("got %d, want 100", got)
	}
}

// TestMakeDomainIDTargetsPartition checks that the synthetic domain-ID generator lands each ID in
// the intended MySQL partition according to the production partitioning helper.
func TestMakeDomainIDTargetsPartition(t *testing.T) {
	nbits := mysql.NumBitsForPartitionCount(partitionCount)
	for partition := 0; partition < partitionCount; partition++ {
		id := makeDomainID(partition, uint64(partition+1))
		got := mysql.PartitionByIdMSB(&id, nbits)
		if int(got) != partition {
			t.Fatalf("partition mismatch: got %d want %d", got, partition)
		}
	}
}

// TestAggregateIDs checks that aggregateIDs sorts and hashes IDs into a non-zero payload digest
// and reports the expected glued-payload byte length.
func TestAggregateIDs(t *testing.T) {
	id, length := aggregateIDs([]common.SHA256Output{
		makeLinearID(0x40, 3),
		makeLinearID(0x40, 1),
		makeLinearID(0x40, 2),
	})
	if id == ([32]byte{}) {
		t.Fatal("expected non-zero hash")
	}
	if length != 3*32 {
		t.Fatalf("unexpected length: %d", length)
	}
}

// TestPercentileDuration checks the basic summary-stat helpers used in benchmark reporting.
func TestPercentileDuration(t *testing.T) {
	values := []time.Duration{5 * time.Second, time.Second, 3 * time.Second, 2 * time.Second}
	median := medianDuration(values)
	if median != 3*time.Second {
		t.Fatalf("median mismatch: %v", median)
	}
	iqr := iqrDuration(values)
	if iqr <= 0 {
		t.Fatalf("iqr should be positive: %v", iqr)
	}
}

// TestBenchmarkDBNameIncludesWorkloadFlags checks that generated benchmark schema names stay
// non-empty, keep the safety prefix, and change when the run label changes.
func TestBenchmarkDBNameIncludesWorkloadFlags(t *testing.T) {
	got := benchmarkDBName("new", "small", "little", 25, "pair-01-step-1")
	if got == "" {
		t.Fatal("expected non-empty db name")
	}
	if len(got) > 64 {
		t.Fatalf("db name too long: %d chars: %s", len(got), got)
	}
	if !strings.HasPrefix(got, "bench_coalesce_") {
		t.Fatalf("db name lost safety prefix: %s", got)
	}
	if got == benchmarkDBName("new", "small", "little", 25, "pair-01-step-2") {
		t.Fatalf("db name should change with label: %s", got)
	}
}

// TestBenchmarkDBNameMediumWarmupFitsMySQLLimit checks that a representative benchmark schema
// name stays within MySQL's 64-character identifier limit.
func TestBenchmarkDBNameMediumWarmupFitsMySQLLimit(t *testing.T) {
	got := benchmarkDBName("old", "medium", "no", 0, "warmup-pair-01-step-1")
	if len(got) > 64 {
		t.Fatalf("db name too long for MySQL: %d chars: %s", len(got), got)
	}
}

// TestPrepareRunTempDirCreatesUniqueSubdirectories checks that each benchmark invocation gets its
// own writable run directory under the configured temp root.
func TestPrepareRunTempDirCreatesUniqueSubdirectories(t *testing.T) {
	root := t.TempDir()
	first, err := prepareRunTempDir(root)
	if err != nil {
		t.Fatalf("first prepareRunTempDir failed: %v", err)
	}
	second, err := prepareRunTempDir(root)
	if err != nil {
		t.Fatalf("second prepareRunTempDir failed: %v", err)
	}
	if first == second {
		t.Fatalf("expected unique run directories, got %s", first)
	}
	if !strings.HasPrefix(first, root) || !strings.HasPrefix(second, root) {
		t.Fatalf("run directories must stay under root: %s %s", first, second)
	}
}

type blockingPartitionCaller struct {
	current int32
	maxSeen int32
	sleep   time.Duration
}

func (c *blockingPartitionCaller) callPartition(_ context.Context, _ int) error {
	// Track the maximum number of concurrent calls observed while workers overlap.
	curr := atomic.AddInt32(&c.current, 1)
	for {
		max := atomic.LoadInt32(&c.maxSeen)
		if curr <= max {
			break
		}
		if atomic.CompareAndSwapInt32(&c.maxSeen, max, curr) {
			break
		}
	}
	time.Sleep(c.sleep)
	atomic.AddInt32(&c.current, -1)
	return nil
}

// TestCallPartitionsWithWorkersBoundsConcurrency checks that the worker-pool helper never runs
// more partition calls concurrently than the configured worker limit.
func TestCallPartitionsWithWorkersBoundsConcurrency(t *testing.T) {
	caller := &blockingPartitionCaller{sleep: 5 * time.Millisecond}
	if err := callPartitionsWithWorkers(context.Background(), caller, 4); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := atomic.LoadInt32(&caller.maxSeen); got > 4 {
		t.Fatalf("max concurrency exceeded worker limit: got %d want <= 4", got)
	}
}
