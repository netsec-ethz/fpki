package benchmark

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	"github.com/stretchr/testify/require"
)

func BenchmarkFullUpdate1K(b *testing.B) {
	benchmarkFullUpdate(b, 1000)
}

// BenchmarkFullUpdate10K uses ~ 1438 ms
// Target is updating 17M certs in 2 hours = (linear) = 7200s/17M = 0.424ms per certificate =>
// Target for this test is 0.42 ms * 10K = 4200 ms.
// Linear regression (with 6 points)
// y= 0.1161x + 542.6176 milliseconds
// Linear correlation coefficient is 0.9966
// prediction is y(17M) = 1974243 ms = 1974.243 s = 33 minutes
//
// n log n fitting ( m*x*log(m*x) + c )  (use MSE e.g. mycurvefit.com)
// y= 0.02722022x log(0.02722022x) + 1348.432
// prediction is y(17M) = 2722347 ms = 2722.348 s = 45 minutes
//
// Reproduce and print milliseconds:
// run: go test -run=XXX -bench=FullUpdate ./tests/benchmark/mapserver_benchmark/
// and pipe it to: grep ^BenchmarkFullUpdate | awk '{printf("%30s, %013.6f\n",$1,$3/1000000) }' | \
// sed 's/BenchmarkFullUpdate//'|sed 's/-24//'|sed 's/K/000/'
func BenchmarkFullUpdate10K(b *testing.B) {
	benchmarkFullUpdate(b, 10*1000)
}

func BenchmarkFullUpdate20K(b *testing.B) {
	benchmarkFullUpdate(b, 20*1000)
}

func BenchmarkFullUpdate30K(b *testing.B) {
	benchmarkFullUpdate(b, 30*1000)
}

func BenchmarkFullUpdate40K(b *testing.B) {
	benchmarkFullUpdate(b, 40*1000)
}

func BenchmarkFullUpdate50K(b *testing.B) {
	benchmarkFullUpdate(b, 50*1000)
}

func BenchmarkFullUpdate60K(b *testing.B) {
	benchmarkFullUpdate(b, 60*1000)
}

func BenchmarkFullUpdate70K(b *testing.B) {
	benchmarkFullUpdate(b, 70*1000)
}

func BenchmarkFullUpdate80K(b *testing.B) {
	benchmarkFullUpdate(b, 80*1000)
}

func BenchmarkFullUpdate90K(b *testing.B) {
	benchmarkFullUpdate(b, 90*1000)
}

func BenchmarkFullUpdate100K(b *testing.B) {
	benchmarkFullUpdate(b, 100*1000)
}

func BenchmarkFullUpdate200K(b *testing.B) {
	benchmarkFullUpdate(b, 200*1000)
}

func benchmarkFullUpdate(b *testing.B, count int) {
	expensiveBenchmark(b, count)
	swapBack := swapDBs(b)
	defer swapBack()
	raw, err := gunzip(b, "testdata/certs.pem.gz")
	require.NoError(b, err)
	certs := loadCertsFromPEM(b, raw)

	require.GreaterOrEqual(b, len(certs), count)
	certs = certs[:count]

	ctx, cancelF := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelF()
	up, err := updater.NewMapTestUpdater(nil, 233)
	require.NoError(b, err)

	b.ResetTimer()

	// exec only once, assume perfect measuring. Because b.N is the number of iterations,
	// just mimic b.N executions.
	t0 := time.Now()
	err = up.UpdateCerts(ctx, certs)
	elapsed := time.Since(t0)
	require.NoError(b, err)
	err = up.Close()
	require.NoError(b, err)
	for i := 1; i < b.N; i++ {
		time.Sleep(elapsed)
	}
}

// TestDoUpdatesFromTestDataCerts replaces the DB with an updated DB
// from all certificates in the testdata/certs.pem.gz file.
func TestDoUpdatesFromTestDataCerts(t *testing.T) {
	if os.Getenv("FPKI_TESTS_GENCERTS") == "" {
		t.Skip("not generating new certificates")
	}
	ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancelF()
	swapBack := swapDBs(t)
	defer swapBack()
	fmt.Println("Loading certs ...")
	raw, err := gunzip(t, "testdata/certs.pem.gz")
	require.NoError(t, err)
	certs := loadCertsFromPEM(t, raw)

	db.TruncateAllTablesForTest(t)

	up, err := updater.NewMapTestUpdater(nil, 233)
	require.NoError(t, err)

	batchSize := 10 * 1000
	for i := 0; i < len(certs); i += batchSize {
		certs := certs[i : i+batchSize]
		err = up.UpdateCerts(ctx, certs)
		require.NoError(t, err)
		err = up.CommitSMTChanges(ctx)
		require.NoError(t, err)
		fmt.Printf("Updated %d certs ...\n", i)
	}
	root := up.GetRoot()
	err = up.Close()
	require.NoError(t, err)
	err = ioutil.WriteFile("testdata/root100K.bin", root, 0664)
	require.NoError(t, err)

	// dump contents using mysqldump
	err = exec.Command("bash", "-c", "mysqldump -u root  fpki |gzip - "+
		">testdata/dump100K.sql.gz").Run()
	require.NoError(t, err)
}

// BenchmarkUpdateDomainEntriesUsingCerts10K uses ~ 1246 ms
func BenchmarkUpdateDomainEntriesUsingCerts10K(b *testing.B) {
	benchmarkUpdateDomainEntriesUsingCerts(b, 10*1000)
}

func benchmarkUpdateDomainEntriesUsingCerts(b *testing.B, count int) {
	swapBack := swapDBs(b)
	defer swapBack()
	raw, err := gunzip(b, "testdata/certs.pem.gz")
	require.NoError(b, err)
	certs := loadCertsFromPEM(b, raw)
	require.GreaterOrEqual(b, len(certs), count)
	certs = certs[:count]

	ctx, cancelF := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelF()
	up, err := updater.NewMapTestUpdater(nil, 233)
	require.NoError(b, err)

	b.ResetTimer()

	// exec only once, assume perfect measuring. Because b.N is the number of iterations,
	// just mimic b.N executions.
	t0 := time.Now()
	_, _, err = up.UpdateDomainEntriesUsingCerts(ctx, certs, 10)
	elapsed := time.Since(t0)
	require.NoError(b, err)
	for i := 1; i < b.N; i++ {
		time.Sleep(elapsed)
	}
}

// BenchmarkFetchUpdatedDomainHash10K uses ~ 31 ms
func BenchmarkFetchUpdatedDomainHash10K(b *testing.B) {
	benchmarkFetchUpdatedDomainHash(b, 10*1000)
}

func benchmarkFetchUpdatedDomainHash(b *testing.B, count int) {
	swapBack := swapDBs(b)
	defer swapBack()
	raw, err := gunzip(b, "testdata/certs.pem.gz")
	require.NoError(b, err)
	certs := loadCertsFromPEM(b, raw)
	require.GreaterOrEqual(b, len(certs), count)
	certs = certs[:count]

	ctx, cancelF := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelF()
	up, err := updater.NewMapTestUpdater(nil, 233)
	require.NoError(b, err)
	_, _, err = up.UpdateDomainEntriesUsingCerts(ctx, certs, 10)
	require.NoError(b, err)

	b.ResetTimer()

	// exec only once, assume perfect measuring. Because b.N is the number of iterations,
	// just mimic b.N executions.
	t0 := time.Now()
	_, err = up.FetchUpdatedDomainHash(ctx)
	elapsed := time.Since(t0)
	require.NoError(b, err)
	for i := 1; i < b.N; i++ {
		time.Sleep(elapsed)
	}
}

// BenchmarkRetrieveKeyValuePairDomainEntries10K uses ~ 114 ms
func BenchmarkRetrieveKeyValuePairDomainEntries10K(b *testing.B) {
	benchmarkRetrieveKeyValuePairDomainEntries(b, 10*1000)
}

func benchmarkRetrieveKeyValuePairDomainEntries(b *testing.B, count int) {
	swapBack := swapDBs(b)
	defer swapBack()
	raw, err := gunzip(b, "testdata/certs.pem.gz")
	require.NoError(b, err)
	certs := loadCertsFromPEM(b, raw)
	require.GreaterOrEqual(b, len(certs), count)
	certs = certs[:count]

	ctx, cancelF := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelF()
	up, err := updater.NewMapTestUpdater(nil, 233)
	require.NoError(b, err)
	_, _, err = up.UpdateDomainEntriesUsingCerts(ctx, certs, 10)
	require.NoError(b, err)
	updatedDomainHash, err := up.FetchUpdatedDomainHash(ctx)
	require.NoError(b, err)

	b.ResetTimer()

	// exec only once, assume perfect measuring. Because b.N is the number of iterations,
	// just mimic b.N executions.
	t0 := time.Now()
	_, err = up.Conn().RetrieveKeyValuePairDomainEntries(
		ctx, updatedDomainHash, 10)
	elapsed := time.Since(t0)
	require.NoError(b, err)
	for i := 1; i < b.N; i++ {
		time.Sleep(elapsed)
	}
}

// BenchmarkKeyValuePairToSMTInput10K uses ~ 21 ms
func BenchmarkKeyValuePairToSMTInput10K(b *testing.B) {
	benchmarkKeyValuePairToSMTInput(b, 10*1000)
}

func benchmarkKeyValuePairToSMTInput(b *testing.B, count int) {
	swapBack := swapDBs(b)
	defer swapBack()
	raw, err := gunzip(b, "testdata/certs.pem.gz")
	require.NoError(b, err)
	certs := loadCertsFromPEM(b, raw)
	require.GreaterOrEqual(b, len(certs), count)
	certs = certs[:count]

	ctx, cancelF := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelF()
	up, err := updater.NewMapTestUpdater(nil, 233)
	require.NoError(b, err)
	_, _, err = up.UpdateDomainEntriesUsingCerts(ctx, certs, 10)
	require.NoError(b, err)
	updatedDomainHash, err := up.FetchUpdatedDomainHash(ctx)
	require.NoError(b, err)
	keyValuePairs, err := up.Conn().
		RetrieveKeyValuePairDomainEntries(ctx, updatedDomainHash, 10)
	require.NoError(b, err)

	b.ResetTimer()

	// exec only once, assume perfect measuring. Because b.N is the number of iterations,
	// just mimic b.N executions.
	t0 := time.Now()
	_, _, err = up.KeyValuePairToSMTInput(keyValuePairs)
	elapsed := time.Since(t0)
	require.NoError(b, err)
	for i := 1; i < b.N; i++ {
		time.Sleep(elapsed)
	}
}

// BenchmarkSmtUpdate10K uses ~ 30 ms
func BenchmarkSmtUpdate10K(b *testing.B) {
	benchmarkSmtUpdate(b, 10*1000)
}

func benchmarkSmtUpdate(b *testing.B, count int) {
	swapBack := swapDBs(b)
	defer swapBack()
	raw, err := gunzip(b, "testdata/certs.pem.gz")
	require.NoError(b, err)
	certs := loadCertsFromPEM(b, raw)
	require.GreaterOrEqual(b, len(certs), count)
	certs = certs[:count]

	ctx, cancelF := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelF()
	up, err := updater.NewMapTestUpdater(nil, 233)
	require.NoError(b, err)

	_, _, err = up.UpdateDomainEntriesUsingCerts(ctx, certs, 10)
	require.NoError(b, err)
	updatedDomainHash, err := up.FetchUpdatedDomainHash(ctx)
	require.NoError(b, err)
	keyValuePairs, err := up.Conn().
		RetrieveKeyValuePairDomainEntries(ctx, updatedDomainHash, 10)
	require.NoError(b, err)
	k, v, err := up.KeyValuePairToSMTInput(keyValuePairs)
	require.NoError(b, err)

	b.ResetTimer()

	// exec only once, assume perfect measuring. Because b.N is the number of iterations,
	// just mimic b.N executions.
	t0 := time.Now()
	_, err = up.SMT().Update(ctx, k, v)
	elapsed := time.Since(t0)
	require.NoError(b, err)
	for i := 1; i < b.N; i++ {
		time.Sleep(elapsed)
	}
}

// BenchmarkCommitChanges10K uses ~ 356 ms
func BenchmarkCommitChanges10K(b *testing.B) {
	benchmarkCommitChanges(b, 10*1000)
}

func benchmarkCommitChanges(b *testing.B, count int) {
	swapBack := swapDBs(b)
	defer swapBack()
	raw, err := gunzip(b, "testdata/certs.pem.gz")
	require.NoError(b, err)
	certs := loadCertsFromPEM(b, raw)
	require.GreaterOrEqual(b, len(certs), count)
	certs = certs[:count]

	ctx, cancelF := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelF()
	up, err := updater.NewMapTestUpdater(nil, 233)
	require.NoError(b, err)

	_, _, err = up.UpdateDomainEntriesUsingCerts(ctx, certs, 10)
	require.NoError(b, err)
	updatedDomainHash, err := up.FetchUpdatedDomainHash(ctx)
	require.NoError(b, err)
	keyValuePairs, err := up.Conn().
		RetrieveKeyValuePairDomainEntries(ctx, updatedDomainHash, 10)
	require.NoError(b, err)
	k, v, err := up.KeyValuePairToSMTInput(keyValuePairs)
	require.NoError(b, err)
	_, err = up.SMT().Update(ctx, k, v)
	require.NoError(b, err)

	b.ResetTimer()

	// exec only once, assume perfect measuring. Because b.N is the number of iterations,
	// just mimic b.N executions.
	t0 := time.Now()
	err = up.CommitSMTChanges(ctx)
	elapsed := time.Since(t0)
	require.NoError(b, err)
	for i := 1; i < b.N; i++ {
		time.Sleep(elapsed)
	}
}

// swapDBs swaps a possibly existing production DB with a new one, to be able to perform a test
// TODO(juagargi) ensure that the data from the DB is preserved. Thoughts about this are below:
// IMO this is  hard to do with a function because if it may be called from different
// processes we can't just use e.g. sync.Once, and also returning the DB to the previous state
// even when the test panics would be hard.
// If we just not use a real DB but a mock, this follows better the spirit of a unit test or
// a benchmark, and would not affect any global data.
func swapDBs(t require.TestingT) func() {
	swapBack := func() {
		// this will swap the DB back to its original state
	}
	// prepare the DB for the benchmark
	db.TruncateAllTablesForTest(t)
	return swapBack
}

func gunzip(t require.TestingT, filename string) ([]byte, error) {
	f, err := os.Open(filename)
	require.NoError(t, err)
	z, err := gzip.NewReader(f)
	require.NoError(t, err)

	raw, theErr := io.ReadAll(z)

	err = z.Close()
	require.NoError(t, err)
	err = f.Close()
	require.NoError(t, err)

	return raw, theErr
}

func expensiveBenchmark(b *testing.B, count int) {
	if count > 30000 && os.Getenv("FPKI_BENCH") == "" {
		b.Skip("benchmark is expensive. Skipping")
	}
}
