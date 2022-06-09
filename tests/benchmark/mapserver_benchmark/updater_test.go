package benchmark

import (
	"context"
	"database/sql"
	"io/ioutil"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	"github.com/stretchr/testify/require"
)

func BenchmarkUpdate1K(b *testing.B) {
	benchmarkUpdate(b, 1000)
}

// BenchmarkUpdate10K uses ~ 1438 ms
// Target is updating 17M certs in 2 hours = 7200s/17M = 0.424ms per certificate =>
// Target for this test is 0.42 ms * 10K = 4200 ms.
func BenchmarkUpdate10K(b *testing.B) {
	benchmarkUpdate(b, 10*1000)
}

func benchmarkUpdate(b *testing.B, count int) {
	swapBack := swapDBs(b)
	defer swapBack()
	raw, err := ioutil.ReadFile("testdata/certs.pem")
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
	for i := 1; i < b.N; i++ {
		time.Sleep(elapsed)
	}
}

// BenchmarkUpdateDomainEntriesUsingCerts10K uses ~ 1246 ms
func BenchmarkUpdateDomainEntriesUsingCerts10K(b *testing.B) {
	benchmarkUpdateDomainEntriesUsingCerts(b, 10*1000)
}

func benchmarkUpdateDomainEntriesUsingCerts(b *testing.B, count int) {
	swapBack := swapDBs(b)
	defer swapBack()
	raw, err := ioutil.ReadFile("testdata/certs.pem")
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
	_, err = up.UpdateDomainEntriesUsingCerts(ctx, certs, 10)
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
	raw, err := ioutil.ReadFile("testdata/certs.pem")
	require.NoError(b, err)
	certs := loadCertsFromPEM(b, raw)
	require.GreaterOrEqual(b, len(certs), count)
	certs = certs[:count]

	ctx, cancelF := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelF()
	up, err := updater.NewMapTestUpdater(nil, 233)
	require.NoError(b, err)
	_, err = up.UpdateDomainEntriesUsingCerts(ctx, certs, 10)
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
	raw, err := ioutil.ReadFile("testdata/certs.pem")
	require.NoError(b, err)
	certs := loadCertsFromPEM(b, raw)
	require.GreaterOrEqual(b, len(certs), count)
	certs = certs[:count]

	ctx, cancelF := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelF()
	up, err := updater.NewMapTestUpdater(nil, 233)
	require.NoError(b, err)
	_, err = up.UpdateDomainEntriesUsingCerts(ctx, certs, 10)
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
	raw, err := ioutil.ReadFile("testdata/certs.pem")
	require.NoError(b, err)
	certs := loadCertsFromPEM(b, raw)
	require.GreaterOrEqual(b, len(certs), count)
	certs = certs[:count]

	ctx, cancelF := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelF()
	up, err := updater.NewMapTestUpdater(nil, 233)
	require.NoError(b, err)
	_, err = up.UpdateDomainEntriesUsingCerts(ctx, certs, 10)
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
	raw, err := ioutil.ReadFile("testdata/certs.pem")
	require.NoError(b, err)
	certs := loadCertsFromPEM(b, raw)
	require.GreaterOrEqual(b, len(certs), count)
	certs = certs[:count]

	ctx, cancelF := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelF()
	up, err := updater.NewMapTestUpdater(nil, 233)
	require.NoError(b, err)

	_, err = up.UpdateDomainEntriesUsingCerts(ctx, certs, 10)
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
	db, err := sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/fpki?maxAllowedPacket=1073741824")
	require.NoError(t, err)
	// truncate tables
	_, err = db.Exec("TRUNCATE fpki.domainEntries;")
	require.NoError(t, err)
	_, err = db.Exec("TRUNCATE fpki.tree;")
	require.NoError(t, err)
	_, err = db.Exec("TRUNCATE fpki.updates;")
	require.NoError(t, err)
	// done
	err = db.Close()
	require.NoError(t, err)
	return swapBack
}
