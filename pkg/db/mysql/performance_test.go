package mysql_test

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	mysqllib "github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/require"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/db/mysql"
	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/netsec-ethz/fpki/pkg/tests/random"
	"github.com/netsec-ethz/fpki/pkg/tests/testdb"
	tr "github.com/netsec-ethz/fpki/pkg/tracing"
	"github.com/netsec-ethz/fpki/pkg/util"
)

// TestInsertDeadlock checks that InnoDB gets a deadlock if inserting two records with the
// same ID into the same table from two different go routines.
// InnoDB should not complain if the insert with same IDs is done from the same multi-insert
// SQL statement.
func TestInsertDeadlock(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancelF()

	// Configure a test DB.
	config, removeF := testdb.ConfigureTestDB(t)
	defer removeF()

	// Connect to the DB.
	conn := testdb.Connect(t, config)
	defer conn.Close()

	// Create data to insert into a mock `dirty` table.
	// The data has to be sufficiently large for this test not to be too flaky:
	// All go routines in "clashing_ids" must be inserting simultaneously for the deadlock
	// error to show up.
	NDomains := 1_000
	allDomainIDs := make([]common.SHA256Output, NDomains)
	for i := 0; i < NDomains; i++ {
		binary.LittleEndian.PutUint64(allDomainIDs[i][:], uint64(i))
	}
	t.Log("Mock data ready in memory")

	// Call each thread with different domain IDs separately:
	t.Run("non_overlapping_ids", func(t *testing.T) {
		// Create a dirty table using InnoDB.
		str := "DROP TABLE IF EXISTS `dirty_test`"
		_, err := conn.DB().ExecContext(ctx, str)
		require.NoError(t, err)
		str = `CREATE TABLE dirty_test (
			domain_id VARBINARY(32) NOT NULL,

			PRIMARY KEY(domain_id)
			) ENGINE=InnoDB CHARSET=binary COLLATE=binary
			PARTITION BY LINEAR KEY (domain_id) PARTITIONS 32;`
		_, err = conn.DB().ExecContext(ctx, str)
		require.NoError(t, err)

		callFuncPerIDBatch(32, 100_000, allDomainIDs, func(workerID int, IDs []common.SHA256Output) {
			err := insertIntoDirty(ctx, conn, "dirty_test", IDs)
			require.NoError(t, err)
		})
	})

	// Now call many threads with the same IDs.
	t.Run("clashing_ids", func(t *testing.T) {
		// Create a dirty table using InnoDB.
		str := "DROP TABLE IF EXISTS `dirty_test`"
		_, err := conn.DB().ExecContext(ctx, str)
		require.NoError(t, err)
		str = `CREATE TABLE dirty_test (
			domain_id VARBINARY(32) NOT NULL,

			PRIMARY KEY(domain_id)
			) ENGINE=InnoDB CHARSET=binary COLLATE=binary
			PARTITION BY LINEAR KEY (domain_id) PARTITIONS 32;`
		_, err = conn.DB().ExecContext(ctx, str)
		require.NoError(t, err)

		errors := make([]error, 4)
		wg := sync.WaitGroup{}
		wg.Add(len(errors))
		for i := 0; i < len(errors); i++ {
			i := i
			go func() {
				defer wg.Done()

				// The same IDs, at the same time.
				errors[i] = insertIntoDirty(ctx, conn, "dirty_test", allDomainIDs)
			}()
		}
		wg.Wait()

		// We expect one non-error, and the errors on the rest of the routines.
		successCount := 0
		for _, err := range errors {
			if err != nil {
				require.Error(t, err)
				require.IsType(t, (*mysqllib.MySQLError)(nil), err)
				err := err.(*mysqllib.MySQLError)
				require.Equal(t, uint16(1213), err.Number,
					"got error code: %d\nMySQL Message: %s", err.Number, err.Message)
			} else {
				successCount++
			}
		}
		require.Equal(t, 1, successCount)
	})

	// Same go routine, multiple times the same ID.
	t.Run("same_multi-insert", func(t *testing.T) {
		// Create a dirty table using InnoDB.
		str := "DROP TABLE IF EXISTS `dirty_test`"
		_, err := conn.DB().ExecContext(ctx, str)
		require.NoError(t, err)
		str = `CREATE TABLE dirty_test (
			domain_id VARBINARY(32) NOT NULL,

			PRIMARY KEY(domain_id)
			) ENGINE=InnoDB CHARSET=binary COLLATE=binary
			PARTITION BY LINEAR KEY (domain_id) PARTITIONS 32;`
		_, err = conn.DB().ExecContext(ctx, str)
		require.NoError(t, err)

		// Create a slice with all the same IDs.
		sameIDs := allDomainIDs[:0]
		firstID := allDomainIDs[0]
		for i := 0; i < len(allDomainIDs); i++ {
			localCopy := firstID
			sameIDs = append(sameIDs, localCopy)
		}
		err = insertIntoDirty(ctx, conn, "dirty_test", sameIDs)
		require.NoError(t, err)
	})
}

// BenchmarkInsertPerformance tests the insert performance using different approaches, in articuno:
// BenchmarkInsertPerformance/MyISAM (58.31s)
// BenchmarkInsertPerformance/InnoDB (54.51s)
func BenchmarkInsertPerformance(b *testing.B) {
	ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancelF()

	// Configure a test DB.
	config, removeF := testdb.ConfigureTestDB(b)
	defer removeF()

	// Connect to the DB.
	conn := testdb.Connect(b, config)
	defer conn.Close()

	// Create lots of data to insert into the `certs` table.
	// NCerts := 10_000_000
	NCerts := 5_000_000
	BatchSize := 10_000
	NWorkers := 64
	if testing.Short() {
		// Make the test much shorter.
		BatchSize = 10000
		NWorkers = 8
		NCerts = NWorkers * BatchSize
	}
	require.Equal(b, 0, NCerts%BatchSize, "there is an error in the test setup. NCerts must be a "+
		"multiple of BatchSize, modify either of them")
	// From xenon2025h1 we have an average of 1100b/cert
	PayloadSize := 1_100
	allCertIDs := make([]common.SHA256Output, NCerts)
	for i := 0; i < NCerts; i++ {
		binary.LittleEndian.PutUint64(allCertIDs[i][:], uint64(i))
	}
	rand.Shuffle(len(allCertIDs), func(i, j int) {
		allCertIDs[i], allCertIDs[j] = allCertIDs[j], allCertIDs[i]
	})
	mockExp := time.Unix(42, 0)
	mockPayload := make([]byte, PayloadSize)
	b.Log("Mock data ready in memory")

	// Note that InnoDB works much faster with insertions with AUTO INCREMENT.
	b.Run("InnoDB", func(b *testing.B) {
		tests.SkipExpensiveTest(b)
		// Create a certs-like table using MyISAM.
		str := "DROP TABLE IF EXISTS `insert_test`"
		_, err := conn.DB().ExecContext(ctx, str)
		require.NoError(b, err)
		str = `CREATE TABLE insert_test (
			auto_id BIGINT NOT NULL AUTO_INCREMENT,
			cert_id VARBINARY(32) NOT NULL,
			parent_id VARBINARY(32) DEFAULT NULL,
			expiration DATETIME NOT NULL,
			payload LONGBLOB,

			PRIMARY KEY(auto_id),
			UNIQUE KEY(cert_id)
		  ) ENGINE=InnoDB CHARSET=binary COLLATE=binary;`
		_, err = conn.DB().ExecContext(ctx, str)
		require.NoError(b, err)

		str = "ALTER INSTANCE DISABLE INNODB REDO_LOG;"
		_, err = conn.DB().ExecContext(ctx, str)
		require.NoError(b, err)

		// Also TAL at the WithDefaults() function.
		str = "SET autocommit=0;"
		_, err = conn.DB().ExecContext(ctx, str)
		require.NoError(b, err)

		str = "SET unique_checks=0;"
		_, err = conn.DB().ExecContext(ctx, str)
		require.NoError(b, err)

		str = "START TRANSACTION"
		_, err = conn.DB().ExecContext(ctx, str)
		require.NoError(b, err)

		callFuncPerIDBatch(NWorkers, BatchSize, allCertIDs, func(workerID int, IDs []common.SHA256Output) {
			insertCerts(ctx, b, conn, "insert_test", IDs, mockExp, mockPayload)
		})

		str = "COMMIT"
		_, err = conn.DB().ExecContext(ctx, str)
		require.NoError(b, err)

		str = "SET unique_checks=1;"
		_, err = conn.DB().ExecContext(ctx, str)
		require.NoError(b, err)

		str = "ALTER INSTANCE DISABLE INNODB REDO_LOG;"
		_, err = conn.DB().ExecContext(ctx, str)
		require.NoError(b, err)
	})

	// Create a certs-like table using MyISAM.
	// 58K certs/s using articuno.
	b.Run("MyISAM", func(b *testing.B) {
		str := "DROP TABLE IF EXISTS `insert_test`"
		_, err := conn.DB().ExecContext(ctx, str)
		require.NoError(b, err)
		str = `CREATE TABLE insert_test (
			cert_id VARBINARY(32) NOT NULL,
			expiration DATETIME NOT NULL,
			payload LONGBLOB,

			PRIMARY KEY(cert_id)
		) ENGINE=MyISAM CHARSET=binary COLLATE=binary;`
		_, err = conn.DB().ExecContext(ctx, str)
		require.NoError(b, err)

		callFuncPerIDBatch(NWorkers, BatchSize, allCertIDs, func(workerID int, IDs []common.SHA256Output) {
			insertCerts(ctx, b, conn, "insert_test", IDs, mockExp, mockPayload)
		})
	})

	CSVFilePath := "/mnt/data/tmp/insert_test_data.csv"
	b.Run("create_data_to_csv", func(b *testing.B) {
		writeCSV(b, CSVFilePath, recordsFromCertIDs(allCertIDs, mockExp, mockPayload))
	})
	b.Run("save_table_to_csv", func(b *testing.B) {
		tests.SkipExpensiveTest(b)
		str := "DROP TABLE IF EXISTS `insert_test`"
		_, err := conn.DB().ExecContext(ctx, str)
		require.NoError(b, err)
		str = `CREATE TABLE insert_test (
			cert_id VARBINARY(32) NOT NULL,
			expiration DATETIME NOT NULL,
			payload LONGBLOB,

			PRIMARY KEY(cert_id)
		) ENGINE=MyISAM CHARSET=binary COLLATE=binary;`
		_, err = conn.DB().ExecContext(ctx, str)
		require.NoError(b, err)

		callFuncPerIDBatch(NWorkers, BatchSize, allCertIDs, func(workerID int, IDs []common.SHA256Output) {
			insertCerts(ctx, b, conn, "insert_test", IDs, mockExp, mockPayload)
		})

		str = `SELECT TO_BASE64(cert_id),expiration,TO_BASE64(payload) FROM insert_test INTO OUTFILE ? ` +
			`FIELDS TERMINATED BY ',' ENCLOSED BY '"' ` +
			`LINES TERMINATED BY '\n'`
		_, err = conn.DB().ExecContext(ctx, str, CSVFilePath)
		require.NoError(b, err)
	})

	// Load a file directly.
	// In articuno it takes 78s, that is, 64K certs/s (file not in RAID)
	// In articuno it takes 65s, that is, 77K certs/s (file in RAID)
	b.Run("load_data_myisam", func(b *testing.B) {
		str := "DROP TABLE IF EXISTS `insert_test`"
		_, err := conn.DB().ExecContext(ctx, str)
		require.NoError(b, err)
		str = `CREATE TABLE insert_test (
			cert_id VARBINARY(32) NOT NULL,
			expiration DATETIME NOT NULL,
			payload LONGBLOB,

			PRIMARY KEY(cert_id)
		) ENGINE=MyISAM CHARSET=binary COLLATE=binary;`
		_, err = conn.DB().ExecContext(ctx, str)
		require.NoError(b, err)

		loadDataWithCSV(ctx, b, conn, CSVFilePath)
	})
}

// BenchmarkPartitionInsert tests the performance of inserting data into a certs-like table,
//
// using different approaches, in particular, partitioning the CSV file and table as well.
//
// Preliminary results: (running in local computer, with -short, that is, 800K certs)
// TestPartitionInsert/load_data/myisam (13.94s)
// TestPartitionInsert/load_data/innodb/single (21.36s)
// TestPartitionInsert/load_data/innodb/parallel/load_0_partitions (15.30s)
//
// Results at articuno (with -short):
// TestPartitionInsert/load_data/myisam (11.56s)
// TestPartitionInsert/load_data/innodb/single (14.15s)
// TestPartitionInsert/load_data/innodb/parallel/load_0_partitions (3.92s)
//
// ------------------------  [OBSOLETE] --------------------------
// Results at articuno long test:
// TestPartitionInsert/load_data/innodb/parallel/load_0_partitions (57.92s)
//
// ------------------------  [OBSOLETE] --------------------------
// Results at articuno, long test with innodb_page_size = 64K:
// TestPartitionInsert/load_data/innodb/parallel/load_0_partitions (29.05s)
//
// ------------------------  [CURRENT STATUS] --------------------------
// Results at articuno, long test with innodb_page_size = 64K and new RAID0 chunk of 64Kb:
// TestPartitionInsert/load_data/myisam (77.64s)
// TestPartitionInsert/load_data/innodb/single (89.92s)
// TestPartitionInsert/load_data/innodb/parallel/load_0_partitions (17.03s)
//
// TestPartitionInsert/load_data/innodb/parallel/range/16 (13.46s)
// TestPartitionInsert/load_data/innodb/parallel/range/32 (12.33s)
// TestPartitionInsert/load_data/innodb/parallel/range/64 (12.03s)
// TestPartitionInsert/load_data/innodb/parallel/range/sorted16 (13.46s)
// TestPartitionInsert/load_data/innodb/parallel/range/sorted32 (12.28s)
// TestPartitionInsert/load_data/innodb/parallel/range/sorted64 (12.20s)
// TestPartitionInsert/load_data/innodb/parallel/range/inverse32 (11.67s)
// TestPartitionInsert/load_data/innodb/parallel/range/inverse64 (12.00s)
//
// TestPartitionInsert/load_data/innodb/parallel/key/32 (11.64s)
// TestPartitionInsert/load_data/innodb/parallel/key/64 (12.47s)
// TestPartitionInsert/load_data/innodb/parallel/key/sorted32 (12.00s)
// TestPartitionInsert/load_data/innodb/parallel/key/inverse32 (11.98s)
//
// TestPartitionInsert/load_data/innodb/parallel/linear/32 (14.00s)
// TestPartitionInsert/load_data/innodb/parallel/linear/64 (16.70s)
// TestPartitionInsert/load_data/innodb/parallel/linear/sorted32 (16.00s)
// TestPartitionInsert/load_data/innodb/parallel/linear/sorted64 (14.78s)
// TestPartitionInsert/load_data/innodb/parallel/linear/inverse32 (11.56s)
// TestPartitionInsert/load_data/innodb/parallel/linear/inverse64 (14.02s)
//
// ------------------------  [BENCHMARK STATUS] --------------------------
// Only for linear, two runs:
//
// goos: linux
// goarch: amd64
// pkg: github.com/netsec-ethz/fpki/pkg/db/mysql
// cpu: Intel(R) Xeon(R) Gold 6242 CPU @ 2.80GHz
// BenchmarkPartitionInsert/innodb/parallel/linear/2/load_only-32         	       1	47478200162 ns/op
// BenchmarkPartitionInsert/innodb/parallel/linear/4/load_only-32         	       1	25007699646 ns/op
// BenchmarkPartitionInsert/innodb/parallel/linear/8/load_only-32         	       1	14927805653 ns/op
// BenchmarkPartitionInsert/innodb/parallel/linear/16/load_only-32        	       1	8559264786 ns/op
// BenchmarkPartitionInsert/innodb/parallel/linear/32/load_only-32        	       1	4809242874 ns/op
// BenchmarkPartitionInsert/innodb/parallel/linear/64/load_only-32        	       1	4713565653 ns/op
// BenchmarkPartitionInsert/innodb/parallel/linear/sorted2/load_only-32   	       1	44825781781 ns/op
// BenchmarkPartitionInsert/innodb/parallel/linear/sorted4/load_only-32   	       1	26451970662 ns/op
// BenchmarkPartitionInsert/innodb/parallel/linear/sorted8/load_only-32   	       1	14734631174 ns/op
// BenchmarkPartitionInsert/innodb/parallel/linear/sorted16/load_only-32  	       1	8264559184 ns/op
// BenchmarkPartitionInsert/innodb/parallel/linear/sorted32/load_only-32  	       1	4873683350 ns/op
// BenchmarkPartitionInsert/innodb/parallel/linear/sorted64/load_only-32  	       1	4610484153 ns/op
// BenchmarkPartitionInsert/innodb/parallel/linear/inverse2/load_only-32  	       1	46984741498 ns/op
// BenchmarkPartitionInsert/innodb/parallel/linear/inverse4/load_only-32  	       1	29170276264 ns/op
// BenchmarkPartitionInsert/innodb/parallel/linear/inverse8/load_only-32  	       1	15069563037 ns/op
// BenchmarkPartitionInsert/innodb/parallel/linear/inverse16/load_only-32 	       1	12772204752 ns/op
// BenchmarkPartitionInsert/innodb/parallel/linear/inverse32/load_only-32 	       1	6973776232 ns/op
// BenchmarkPartitionInsert/innodb/parallel/linear/inverse64/load_only-32 	       1	6751716890 ns/op
//
// BenchmarkPartitionInsert/innodb/parallel/linear/2/load_only-32         	       1	46316287235 ns/op
// BenchmarkPartitionInsert/innodb/parallel/linear/4/load_only-32         	       1	26804651970 ns/op
// BenchmarkPartitionInsert/innodb/parallel/linear/8/load_only-32         	       1	14177246764 ns/op
// BenchmarkPartitionInsert/innodb/parallel/linear/16/load_only-32        	       1	8731915781 ns/op
// BenchmarkPartitionInsert/innodb/parallel/linear/32/load_only-32        	       1	7206455873 ns/op
// BenchmarkPartitionInsert/innodb/parallel/linear/64/load_only-32        	       1	5365581642 ns/op
// BenchmarkPartitionInsert/innodb/parallel/linear/sorted2/load_only-32   	       1	47264175002 ns/op
// BenchmarkPartitionInsert/innodb/parallel/linear/sorted4/load_only-32   	       1	27693145674 ns/op
// BenchmarkPartitionInsert/innodb/parallel/linear/sorted8/load_only-32   	       1	14701929265 ns/op
// BenchmarkPartitionInsert/innodb/parallel/linear/sorted16/load_only-32  	       1	9979814845 ns/op
// BenchmarkPartitionInsert/innodb/parallel/linear/sorted32/load_only-32  	       1	4800589391 ns/op
// BenchmarkPartitionInsert/innodb/parallel/linear/sorted64/load_only-32  	       1	4840803067 ns/op
// BenchmarkPartitionInsert/innodb/parallel/linear/inverse2/load_only-32  	       1	42180543117 ns/op
// BenchmarkPartitionInsert/innodb/parallel/linear/inverse4/load_only-32  	       1	25059406480 ns/op
// BenchmarkPartitionInsert/innodb/parallel/linear/inverse8/load_only-32  	       1	13123920949 ns/op
// BenchmarkPartitionInsert/innodb/parallel/linear/inverse16/load_only-32 	       1	7647975636 ns/op
// BenchmarkPartitionInsert/innodb/parallel/linear/inverse32/load_only-32 	       1	4504448913 ns/op
// BenchmarkPartitionInsert/innodb/parallel/linear/inverse64/load_only-32 	       1	4540372700 ns/op
//
// Summary:
// - The page size was extremely important.
// - Reconfiguring the RAID with an appropriate chunk of 64Kb was extremely important.
// - Inserting in parallel with InnoDB is faster than MyISAM
// - Partitioning helps performance, up to a certain number of them.
// - Sorting the entries, so that each thread always cares about the same range,
// does NOT help performance; it doesn't hurt it either.
// We can use sorting to assign IDs to different workers, to avoid
// dead-locks for large multi-inserts.
//
// We decide to use 32 partitions, linear key, inverse sorted data, as we anyway will be "sorting"
// (aka dispatching) the data to avoid deadlocks.
// The reason that the inverse sorted data is faster might be because each thread will attack
// many partitions, while straight sorted data means each thread uses just one.
// We could use KEY for partitions, but the data is sorted anyway.
func BenchmarkPartitionInsert(b *testing.B) {
	defer util.ShutdownFunction()
	ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancelF()

	// Tracing.
	tr.SetGlobalTracerName("partition-insert-benchmark")
	ctx, span := tr.MT().Start(ctx, "benchmark")
	defer span.End()

	// Configure a test DB.
	config, removeF := testdb.ConfigureTestDB(b)
	defer removeF()

	// Connect to the DB.
	conn := testdb.Connect(b, config)
	defer conn.Close()

	exec := func(t tests.T, query string, args ...any) {
		exec(ctx, t, conn, query, args...)
	}

	NCerts := 5_000_000
	BatchSize := 10_000
	NWorkers := 64
	if testing.Short() {
		// Make the test much shorter, 800K certs only.
		BatchSize = 10_000
		NWorkers = 8
		NCerts = 10 * NWorkers * BatchSize
	}
	require.Equal(b, 0, NCerts%BatchSize, "there is an error in the test setup. NCerts must be a "+
		"multiple of BatchSize, modify either of them")

	// Create benchmark's mock data.
	var records [][]string
	{
		_, span := tr.T("create-data").Start(ctx, "create-data")

		allCertIDs := mockTestData(b, NCerts)
		mockExp := time.Unix(42, 0)
		mockPayload := make([]byte, 1_100) // From xenon2025h1 we have an average of 1100b/cert
		records = recordsFromCertIDs(allCertIDs, mockExp, mockPayload)
		require.Equal(b, NCerts, len(records))
		b.Logf("Mock data ready in memory, %d certs", NCerts)

		span.End()
	}

	CSVFilePath := "/mnt/data/tmp/insert_test_data.csv"

	dropTable := func(t tests.T) {
		exec(t, "DROP TABLE IF EXISTS `insert_test`")
	}
	createCsv := func(t tests.T) {
		_, span := tr.T("file").Start(ctx, "create-csv-file")
		writeCSV(t, CSVFilePath, records)
		span.End()
	}
	b.Run("myisam", func(b *testing.B) {
		createCsv(b)
		dropTable(b)
		exec(b, `CREATE TABLE insert_test (
				cert_id VARBINARY(32) NOT NULL,
				parent_id VARBINARY(32) DEFAULT NULL,
				expiration DATETIME NOT NULL,
				payload LONGBLOB,
				PRIMARY KEY(cert_id)
			) ENGINE=MyISAM CHARSET=binary COLLATE=binary;`)
		loadDataWithCSV(ctx, b, conn, CSVFilePath)
	})
	b.Run("innodb", func(b *testing.B) {
		dropTable(b)
		exec(b, `CREATE TABLE insert_test (
				auto_id BIGINT NOT NULL AUTO_INCREMENT,
				cert_id VARBINARY(32) NOT NULL,
				parent_id VARBINARY(32) DEFAULT NULL,
				expiration DATETIME NOT NULL,
				payload LONGBLOB,
				PRIMARY KEY(auto_id),
				UNIQUE KEY(cert_id)
			) ENGINE=InnoDB CHARSET=binary COLLATE=binary;`)

		b.Run("single", func(b *testing.B) {
			createCsv(b)
			// For better performance with InnoDB while loading bulk data, TAL:
			// https://dev.mysql.com/doc/refman/8.3/en/optimizing-innodb-bulk-data-loading.html
			defer tests.ExtendTimeForBenchmark(b)()
			loadDataWithCSV(ctx, b, conn, CSVFilePath)
		})
		b.Run("parallel", func(b *testing.B) {
			NWorkers := NWorkers // Use the same value

			chunkFilePath := func(workerIndex int) string {
				return csvChunkFileName(CSVFilePath, "", workerIndex)
			}
			chunkFilePathSorted := func(workerIndex int) string {
				return csvChunkFileName(CSVFilePath, "sorted", workerIndex)
			}

			// Function to split all the data in N CSV files.
			splitFile := func(t tests.T, numParts int) {
				_, span := tr.T("file").Start(ctx, "csv-file-split")
				writeChunkedCsv(t, chunkFilePath, numParts, records)
				span.End()
			}

			// Function to split all the data in N CSV files, where each file contains
			// records sorted by the result of the hasher function applied to cert_id.
			splitFileSorted := func(t tests.T, N int, hasher func(*common.SHA256Output, int) uint) {
				_, span := tr.T("file").Start(ctx, "split-sorted")
				writeSortedChunkedCsv(ctx, t, records, N, hasher, chunkFilePathSorted)
				span.End()
			}

			runPartitionTest := func(b *testing.B, N int, createF func(tests.T, int)) {
				defer tests.ExtendTimeForBenchmark(b)()
				splitFile(b, N)
				runWithCsvFile(ctx, b, conn, N, createF, chunkFilePath)
			}
			runMsbSortedPartitionTest := func(b *testing.B, N int, createF func(tests.T, int)) {
				defer tests.ExtendTimeForBenchmark(b)()
				splitFileSorted(b, N, hasherMSB)
				runWithCsvFile(ctx, b, conn, N, createF, chunkFilePathSorted)
			}
			runLsbSortedPartitionTest := func(b *testing.B, N int, createF func(tests.T, int)) {
				defer tests.ExtendTimeForBenchmark(b)()
				splitFileSorted(b, N, hasherLSB)
				runWithCsvFile(ctx, b, conn, N, createF, chunkFilePathSorted)
			}

			b.Run("load_0_partitions", func(b *testing.B) {
				splitFile(b, NWorkers)
				b.Run("load_only", func(b *testing.B) {
					defer tests.ExtendTimeForBenchmark(b)()
					runWithCsvFile(ctx, b, conn, NWorkers, nil, chunkFilePath)
				})
				removeChunkedCsv(b, chunkFilePath, NWorkers)
			})
			b.Run("range", func(b *testing.B) {
				createTable := func(t tests.T, numPartitions int) {
					str := "CREATE TABLE insert_test ( " +
						"cert_id VARBINARY(32) NOT NULL," +
						"parent_id VARBINARY(32) DEFAULT NULL," +
						"expiration DATETIME NOT NULL," +
						"payload LONGBLOB," +
						"PRIMARY KEY(cert_id)" +
						") ENGINE=InnoDB CHARSET=binary COLLATE=binary " +
						"PARTITION BY RANGE COLUMNS (cert_id) (\n" + "%s" + "\n);"

					perPartition := make([]string, numPartitions)
					// Each partition splits the range in 256 / numParts
					for i := 0; i < numPartitions; i++ {
						perPartition[i] =
							fmt.Sprintf("partition p%02d values less than (x'%02x%s')",
								i,
								(i+1)*256/numPartitions,
								strings.Repeat("00", 31))
					}
					perPartition[numPartitions-1] =
						fmt.Sprintf("PARTITION p%d VALUES LESS THAN (MAXVALUE)", numPartitions-1)
					str = fmt.Sprintf(str, strings.Join(perPartition, ",\n"))

					dropTable(t)
					exec(t, str)
				}

				b.Run("2", func(b *testing.B) {
					runPartitionTest(b, 2, createTable)
				})
				b.Run("4", func(b *testing.B) {
					runPartitionTest(b, 4, createTable)
				})
				b.Run("8", func(b *testing.B) {
					runPartitionTest(b, 8, createTable)
				})
				b.Run("16", func(b *testing.B) {
					runPartitionTest(b, 16, createTable)
				})
				b.Run("32", func(b *testing.B) {
					runPartitionTest(b, 32, createTable)
				})
				b.Run("64", func(b *testing.B) {
					runPartitionTest(b, 64, createTable)
				})
				// Sorted data tests.
				b.Run("sorted2", func(b *testing.B) {
					runMsbSortedPartitionTest(b, 2, createTable)
				})
				b.Run("sorted4", func(b *testing.B) {
					runMsbSortedPartitionTest(b, 4, createTable)
				})
				b.Run("sorted8", func(b *testing.B) {
					runMsbSortedPartitionTest(b, 8, createTable)
				})
				b.Run("sorted16", func(b *testing.B) {
					runMsbSortedPartitionTest(b, 16, createTable)
				})
				b.Run("sorted32", func(b *testing.B) {
					runMsbSortedPartitionTest(b, 32, createTable)
				})
				b.Run("sorted64", func(b *testing.B) {
					runMsbSortedPartitionTest(b, 64, createTable)
				})
				b.Run("inverse32", func(b *testing.B) {
					runLsbSortedPartitionTest(b, 32, createTable)
				})
				b.Run("inverse64", func(b *testing.B) {
					runLsbSortedPartitionTest(b, 64, createTable)
				})
			})

			b.Run("key", func(b *testing.B) {
				// Creates a table partitioned by key, linearly. The LSBs are used.
				createTable := func(t tests.T, numPartitions int) {
					str := fmt.Sprintf(
						"CREATE TABLE insert_test ( "+
							"cert_id VARBINARY(32) NOT NULL,"+
							"parent_id VARBINARY(32) DEFAULT NULL,"+
							"expiration DATETIME NOT NULL,"+
							"payload LONGBLOB,"+
							"PRIMARY KEY(cert_id)"+
							") ENGINE=InnoDB CHARSET=binary COLLATE=binary "+
							"PARTITION BY KEY (cert_id) PARTITIONS %d;",
						numPartitions)

					dropTable(t)
					exec(t, str)
				}

				b.Run("8", func(b *testing.B) {
					runPartitionTest(b, 8, createTable)
				})
				b.Run("32", func(b *testing.B) {
					runPartitionTest(b, 32, createTable)
				})
				b.Run("64", func(b *testing.B) {
					runPartitionTest(b, 64, createTable)
				})

				b.Run("sorted32", func(b *testing.B) {
					runLsbSortedPartitionTest(b, 32, createTable)
				})
				b.Run("inverse32", func(b *testing.B) {
					runMsbSortedPartitionTest(b, 32, createTable)
				})
			})

			b.Run("linear", func(b *testing.B) {
				// Creates a table partitioned by key, linearly. The LSBs are used.
				createTable := func(t tests.T, numPartitions int) {
					str := fmt.Sprintf(
						"CREATE TABLE insert_test ( "+
							"cert_id VARBINARY(32) NOT NULL,"+
							"parent_id VARBINARY(32) DEFAULT NULL,"+
							"expiration DATETIME NOT NULL,"+
							"payload LONGBLOB,"+
							"PRIMARY KEY(cert_id)"+
							") ENGINE=InnoDB CHARSET=binary COLLATE=binary "+
							"PARTITION BY LINEAR KEY (cert_id) PARTITIONS %d;",
						numPartitions)

					dropTable(t)
					exec(t, str)
				}

				b.Run("2", func(b *testing.B) {
					runPartitionTest(b, 2, createTable)
				})
				b.Run("4", func(b *testing.B) {
					runPartitionTest(b, 4, createTable)
				})
				b.Run("8", func(b *testing.B) {
					runPartitionTest(b, 8, createTable)
				})
				b.Run("16", func(b *testing.B) {
					runPartitionTest(b, 16, createTable)
				})
				b.Run("32", func(b *testing.B) {
					runPartitionTest(b, 32, createTable)
				})
				b.Run("64", func(b *testing.B) {
					runPartitionTest(b, 64, createTable)
				})
				// Sorted data tests.
				b.Run("sorted2", func(b *testing.B) {
					runLsbSortedPartitionTest(b, 2, createTable)
				})
				b.Run("sorted4", func(b *testing.B) {
					runLsbSortedPartitionTest(b, 4, createTable)
				})
				b.Run("sorted8", func(b *testing.B) {
					runLsbSortedPartitionTest(b, 8, createTable)
				})
				b.Run("sorted16", func(b *testing.B) {
					runLsbSortedPartitionTest(b, 16, createTable)
				})
				b.Run("sorted32", func(b *testing.B) {
					runLsbSortedPartitionTest(b, 32, createTable)
				})
				b.Run("sorted64", func(b *testing.B) {
					runLsbSortedPartitionTest(b, 64, createTable)
				})
				// Inverse data tests.
				b.Run("inverse2", func(b *testing.B) {
					runMsbSortedPartitionTest(b, 2, createTable)
				})
				b.Run("inverse4", func(b *testing.B) {
					runMsbSortedPartitionTest(b, 4, createTable)
				})
				b.Run("inverse8", func(b *testing.B) {
					runMsbSortedPartitionTest(b, 8, createTable)
				})
				b.Run("inverse16", func(b *testing.B) {
					runMsbSortedPartitionTest(b, 16, createTable)
				})
				b.Run("inverse32", func(b *testing.B) {
					runMsbSortedPartitionTest(b, 32, createTable)
				})
				b.Run("inverse64", func(b *testing.B) {
					runMsbSortedPartitionTest(b, 64, createTable)
				})
			})
		})
	})
}

// TestReadPerformance checks the performance that db.RetrieveCertificatePayloads will experiment.
// We try both MyISAM and InnoDB tables, all with queries in parallel.

// Results at articuno:

// TestReadPerformance/myisam/retrieve_only/8 (2.52s)
// TestReadPerformance/myisam/retrieve_only32 (1.22s)
// TestReadPerformance/myisam/retrieve_only/64 (1.17s)
// TestReadPerformance/myisam/retrieve_only/128 (1.11s)
// TestReadPerformance/myisam/retrieve_only/256 (1.03s)
// TestReadPerformance/myisam/retrieve_only/512 (0.82s)

// TestReadPerformance/innodb/no_partitions/retrieve_only/8 (2.19s)
// TestReadPerformance/innodb/no_partitions/retrieve_only32 (0.90s)
// TestReadPerformance/innodb/no_partitions/retrieve_only/64 (0.85s)
// TestReadPerformance/innodb/no_partitions/retrieve_only/128 (0.84s)
// TestReadPerformance/innodb/no_partitions/retrieve_only/256 (0.78s)
// TestReadPerformance/innodb/no_partitions/retrieve_only/512 (0.70s)

// The partitions tests retrieve 25_000_000 certificates.

// TestReadPerformance/innodb/partitioned/32_partitions_linear/retrieve_only/8 (15.80s)		1582278 certs/s
// TestReadPerformance/innodb/partitioned/32_partitions_linear/retrieve_only32 (5.89s)		4244482 certs/s
// TestReadPerformance/innodb/partitioned/32_partitions_linear/retrieve_only/64 (5.57s)		4488330 certs/s
// TestReadPerformance/innodb/partitioned/32_partitions_linear/retrieve_only/128 (4.81s)	5197505 certs/s
// TestReadPerformance/innodb/partitioned/32_partitions_linear/retrieve_only/256 (4.62s)	5411255 certs/s
// TestReadPerformance/innodb/partitioned/32_partitions_linear/retrieve_only/512 (4.81s)	5197505 certs/s

// TestReadPerformance/innodb/partitioned/64_partitions_linear/retrieve_only/8 (15.14s)		1651255 certs/s
// TestReadPerformance/innodb/partitioned/64_partitions_linear/retrieve_only32 (5.45s)		4587156 certs/s
// TestReadPerformance/innodb/partitioned/64_partitions_linear/retrieve_only/64 (4.91s)		5091650 certs/s
// TestReadPerformance/innodb/partitioned/64_partitions_linear/retrieve_only/128 (4.70s)	5319149 certs/s
// TestReadPerformance/innodb/partitioned/64_partitions_linear/retrieve_only/256 (4.58s)	5458515 certs/s
// TestReadPerformance/innodb/partitioned/64_partitions_linear/retrieve_only/512 (4.67s)	5353319 certs/s

// TestReadPerformance/innodb/partitioned/32_partitions_key/retrieve_only/8 (14.53s)		1720578 certs/s
// TestReadPerformance/innodb/partitioned/32_partitions_key/retrieve_only32 (5.56s)			4496403 certs/s
// TestReadPerformance/innodb/partitioned/32_partitions_key/retrieve_only/64 (5.01s)		4990020 certs/s
// TestReadPerformance/innodb/partitioned/32_partitions_key/retrieve_only/128 (4.64s)		5387931 certs/s
// TestReadPerformance/innodb/partitioned/32_partitions_key/retrieve_only/256 (4.53s)		5518764 certs/s
// TestReadPerformance/innodb/partitioned/32_partitions_key/retrieve_only/512 (4.58s)		5458515 certs/s

// BenchmarkReadPerformance/innodb/partitioned/64_partitions_key/retrieve_only/8 (14.80s)		1689189 certs/s
// BenchmarkReadPerformance/innodb/partitioned/64_partitions_key/retrieve_only32 (5.57s)		4488330 certs/s
// BenchmarkReadPerformance/innodb/partitioned/64_partitions_key/retrieve_only/64 (5.15s)		4854369 certs/s
// BenchmarkReadPerformance/innodb/partitioned/64_partitions_key/retrieve_only/128 (4.57s)		5470460 certs/s
// BenchmarkReadPerformance/innodb/partitioned/64_partitions_key/retrieve_only/256 (4.40s)		5681818 certs/s
// BenchmarkReadPerformance/innodb/partitioned/64_partitions_key/retrieve_only/512 (4.55s)		5494505 certs/s
func BenchmarkReadPerformance(b *testing.B) {
	tests.SkipExpensiveTest(b)

	ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancelF()

	// Configure a test DB.
	config, removeF := testdb.ConfigureTestDB(b)
	defer removeF()

	// Connect to the DB.
	conn := testdb.Connect(b, config)
	defer conn.Close()

	NCerts := 5_000_000
	BatchSize := 10_000
	NWorkers := 32
	if testing.Short() {
		// Make the test much shorter, 800K certs only.
		BatchSize = 10_000
		NWorkers = 8
		NCerts = 10 * NWorkers * BatchSize
	}
	require.Equal(b, 0, NCerts%BatchSize, "there is an error in the test setup. NCerts must be a "+
		"multiple of BatchSize, modify either of them")

	CSVFilePath := "/mnt/data/tmp/insert_test_data.csv"
	chunkFilePath := func(workerIndex int) string {
		return csvChunkFileName(CSVFilePath, "", workerIndex)
	}
	exec := func(t tests.T, query string, args ...any) {
		exec(ctx, t, conn, query, args...)
	}
	dropTable := func(t tests.T) {
		exec(t, "DROP TABLE IF EXISTS `insert_test`")
	}
	loadCSV := func(t tests.T, filepath string) {
		loadDataWithCSV(ctx, t, conn, filepath)
	}

	allCertIDs := random.RandomIDsForTest(b, NCerts)
	// Create lots of data to insert into the `certs` table.
	// From xenon2025h1 we have an average of 1100b/cert
	PayloadSize := 1_100
	// Shuffle the order of certificates.
	rand.Shuffle(len(allCertIDs), func(i, j int) {
		allCertIDs[i], allCertIDs[j] = allCertIDs[j], allCertIDs[i]
	})
	mockExp := time.Unix(42, 0)
	mockPayload := make([]byte, PayloadSize)
	b.Log("Mock data ready in memory")

	records := recordsFromCertIDs(allCertIDs, mockExp, mockPayload)

	writeChunkedCsv(b, chunkFilePath, NWorkers, records)
	defer removeChunkedCsv(b, chunkFilePath, NWorkers)

	// Function to insert data into a table.
	insertIntoTable := func(t tests.T) {
		// Load those CSV files into the table in parallel.
		wg := sync.WaitGroup{}
		wg.Add(NWorkers)
		for w := 0; w < NWorkers; w++ {
			w := w
			go func() {
				defer wg.Done()

				loadCSV(t, chunkFilePath(w))
			}()
		}
		wg.Wait()
	}

	// Function to retrieve certificate payloads, given their IDs.
	retrieve := func(b *testing.B, NWorkers int, IDs []common.SHA256Output) {
		defer tests.ExtendTimeForBenchmark(b)()
		wg := sync.WaitGroup{}
		wg.Add(NWorkers)
		for w := 0; w < NWorkers; w++ {
			w := w
			batchSize := len(IDs) / NWorkers
			go func() {
				defer wg.Done()
				s := w * batchSize
				e := min(s+batchSize, len(IDs))
				IDs := IDs[s:e]
				retrieveCertificatePayloads(ctx, b, conn, IDs)
			}()
		}
		wg.Wait()
	}

	// Read all certificates using MyISAM. Emulate the RetrieveCertificatesPayloads function.
	b.Run("myisam", func(b *testing.B) {
		dropTable(b)
		exec(b, `CREATE TABLE insert_test (
			cert_id VARBINARY(32) NOT NULL,
			parent_id VARBINARY(32) DEFAULT NULL,
			expiration DATETIME NOT NULL,
			payload LONGBLOB,
			PRIMARY KEY(cert_id)
		) ENGINE=MyISAM CHARSET=binary COLLATE=binary;`)
		insertIntoTable(b)

		b.Run("retrieve_only/8", func(b *testing.B) {
			retrieve(b, 8, allCertIDs)
		})
		b.Run("retrieve_only32", func(b *testing.B) {
			retrieve(b, 32, allCertIDs)
		})
		b.Run("retrieve_only/64", func(b *testing.B) {
			retrieve(b, 64, allCertIDs)
		})
		b.Run("retrieve_only/128", func(b *testing.B) {
			retrieve(b, 128, allCertIDs)
		})
		b.Run("retrieve_only/256", func(b *testing.B) {
			retrieve(b, 256, allCertIDs)
		})
		b.Run("retrieve_only/512", func(b *testing.B) {
			retrieve(b, 512, allCertIDs)
		})
	})
	b.Run("innodb", func(b *testing.B) {
		b.Run("no_partitions", func(b *testing.B) {
			dropTable(b)
			exec(b, `CREATE TABLE insert_test (
				auto_id BIGINT NOT NULL AUTO_INCREMENT,
				cert_id VARBINARY(32) NOT NULL,
				parent_id VARBINARY(32) DEFAULT NULL,
				expiration DATETIME NOT NULL,
				payload LONGBLOB,
				PRIMARY KEY(auto_id),
				UNIQUE KEY(cert_id)
			) ENGINE=InnoDB CHARSET=binary COLLATE=binary;`)
			insertIntoTable(b)
			// Not necessary: avoid locking the same rows while reading:
			// exec(t, "SET SESSION TRANSACTION ISOLATION LEVEL READ UNCOMMITTED")

			b.Run("retrieve_only/8", func(b *testing.B) {
				retrieve(b, 8, allCertIDs)
			})
			b.Run("retrieve_only32", func(b *testing.B) {
				retrieve(b, 32, allCertIDs)
			})
			b.Run("retrieve_only/64", func(b *testing.B) {
				retrieve(b, 64, allCertIDs)
			})
			b.Run("retrieve_only/128", func(b *testing.B) {
				retrieve(b, 128, allCertIDs)
			})
			b.Run("retrieve_only/256", func(b *testing.B) {
				retrieve(b, 256, allCertIDs)
			})
			b.Run("retrieve_only/512", func(b *testing.B) {
				retrieve(b, 512, allCertIDs)
			})
		})

		b.Run("partitioned", func(b *testing.B) {
			// creates a table partitioned by key.
			createTableKey := func(t tests.T, numPartitions int) {
				str := fmt.Sprintf(
					"CREATE TABLE insert_test ( "+
						"cert_id VARBINARY(32) NOT NULL,"+
						"parent_id VARBINARY(32) DEFAULT NULL,"+
						"expiration DATETIME NOT NULL,"+
						"payload LONGBLOB,"+
						"PRIMARY KEY(cert_id)"+
						") ENGINE=InnoDB CHARSET=binary COLLATE=binary "+
						"PARTITION BY LINEAR KEY (cert_id) PARTITIONS %d;",
					numPartitions)

				dropTable(t)
				exec(t, str)
				insertIntoTable(t)
			}
			// Creates a table partitioned by key, linearly. The LSBs are used.
			createTableLinear := func(t tests.T, numPartitions int) {
				str := fmt.Sprintf(
					"CREATE TABLE insert_test ( "+
						"cert_id VARBINARY(32) NOT NULL,"+
						"parent_id VARBINARY(32) DEFAULT NULL,"+
						"expiration DATETIME NOT NULL,"+
						"payload LONGBLOB,"+
						"PRIMARY KEY(cert_id)"+
						") ENGINE=InnoDB CHARSET=binary COLLATE=binary "+
						"PARTITION BY LINEAR KEY (cert_id) PARTITIONS %d;",
					numPartitions)

				dropTable(t)
				exec(t, str)
				insertIntoTable(t)
			}

			testWithPartitions := func(
				b *testing.B,
				name string,
				tableF func(tests.T, int),
				partCount int,
			) {
				b.Run(fmt.Sprintf("%d_partitions_%s", partCount, name), func(b *testing.B) {
					tableF(b, partCount)
					b.Run("retrieve_only/8", func(b *testing.B) {
						retrieve(b, 8, allCertIDs)
					})
					b.Run("retrieve_only32", func(b *testing.B) {
						retrieve(b, 32, allCertIDs)
					})
					b.Run("retrieve_only/64", func(b *testing.B) {
						retrieve(b, 64, allCertIDs)
					})
					b.Run("retrieve_only/128", func(b *testing.B) {
						retrieve(b, 128, allCertIDs)
					})
					b.Run("retrieve_only/256", func(b *testing.B) {
						retrieve(b, 256, allCertIDs)
					})
					b.Run("retrieve_only/512", func(b *testing.B) {
						retrieve(b, 512, allCertIDs)
					})
				})
			}

			// Enlarge the query to have many more items.
			allCertIDs := allCertIDs
			orig := allCertIDs
			extra := make([]common.SHA256Output, len(orig))
			copy(extra, allCertIDs)
			multiplier := 4
			for rep := 0; rep < multiplier; rep++ {
				allCertIDs = append(allCertIDs, extra...)
			}
			fmt.Printf("querying %d certificates\n", len(allCertIDs))

			// Test linear partitions.
			testWithPartitions(b, "linear", createTableLinear, 32)
			testWithPartitions(b, "linear", createTableLinear, 64)

			// Test key partitions.
			testWithPartitions(b, "key", createTableKey, 32)
			testWithPartitions(b, "key", createTableKey, 64)
		})
	})
}

// BenchmarkCreateTableInnoDB measures 126346740 ns/op (0.12s) [mysql-community-server 8.4.2]
func BenchmarkCreateTableInnoDB(b *testing.B) {
	b.SetParallelism(1)
	createFunc := func() {
		db, err := sql.Open("mysql", "root@unix(/var/run/mysqld/mysqld.sock)/")
		require.NoError(b, err)

		strs := []string{
			"DROP DATABASE IF EXISTS testdb",
			"CREATE DATABASE testdb",
			"CREATE TABLE testdb.domains (\n" +
				"  domain_id VARBINARY(32) NOT NULL,\n" +
				"  domain_name VARCHAR(300) COLLATE ascii_bin DEFAULT NULL,\n" +
				"\n" +
				"  PRIMARY KEY (domain_id),\n" +
				"  INDEX domain_name (domain_name)\n" +
				") ENGINE=InnoDB CHARSET=binary COLLATE=binary\n" +
				"PARTITION BY LINEAR KEY (domain_id) PARTITIONS 32",
		}
		for _, str := range strs {
			_, err = db.Exec(str)
			require.NoError(b, err)
		}

		err = db.Close()
		require.NoError(b, err)
	}

	for i := 0; i < b.N; i++ {
		createFunc()
	}
}

// BenchmarkCreateTableMyIsam measures 2130136 ns/op (0.002s) [mysql-community-server 8.4.2]
func BenchmarkCreateTableMyIsam(b *testing.B) {
	b.SetParallelism(1)
	createFunc := func() {
		db, err := sql.Open("mysql", "root@unix(/var/run/mysqld/mysqld.sock)/")
		require.NoError(b, err)

		strs := []string{
			"DROP DATABASE IF EXISTS testdb",
			"CREATE DATABASE testdb",
			"CREATE TABLE testdb.domains (\n" +
				"domain_id VARBINARY(32) NOT NULL,\n" +
				"domain_name VARCHAR(300) COLLATE ascii_bin DEFAULT NULL,\n" +
				"\n" +
				"PRIMARY KEY (domain_id),\n" +
				"INDEX domain_id (domain_id),\n" +
				"INDEX domain_name (domain_name)\n" +
				") ENGINE=MyISAM CHARSET=binary COLLATE=binary;",
		}
		for _, str := range strs {
			_, err = db.Exec(str)
			require.NoError(b, err)
		}

		err = db.Close()
		require.NoError(b, err)
	}

	for i := 0; i < b.N; i++ {
		createFunc()
	}
}

func exec(ctx context.Context, t tests.T, conn db.Conn, query string, args ...any) {
	_, err := conn.DB().ExecContext(ctx, query, args...)
	require.NoError(t, err)
}

func callFuncPerIDBatch(
	numWorkers int,
	batchSize int,
	IDs []common.SHA256Output,
	theFunc func(workerID int, IDs []common.SHA256Output),
) {

	N := len(IDs)
	ch := make(chan []common.SHA256Output)

	// Receive batches.
	wg := sync.WaitGroup{}
	wg.Add(numWorkers)
	for i := 0; i < numWorkers; i++ {
		i := i
		go func() {
			defer wg.Done()

			for batch := range ch {
				theFunc(i, batch)
			}
		}()
	}

	// Send batches.
	startTime := time.Now()
	for i := 0; i < N; i += batchSize {
		s := i
		e := min(N, i+batchSize)

		ch <- IDs[s:e]

		fmt.Printf("new batch received %.2f %%  %.1f certs/s\n",
			float64(i*100)/float64(N), float64(i)/time.Since(startTime).Seconds())
	}
	close(ch)
	wg.Wait()
}

func insertCerts(
	ctx context.Context,
	t tests.T,
	conn db.Conn,
	tableName string,
	certIDs []common.SHA256Output,
	mockExp time.Time,
	mockPayload []byte,
) {

	str := fmt.Sprintf("REPLACE INTO %s (cert_id,expiration,payload) VALUES %s",
		tableName,
		mysql.RepeatStmt(len(certIDs), 3)) // 3 columns
	data := make([]interface{}, 3*len(certIDs))
	for i := range certIDs {
		id := certIDs[i]
		data[i*3] = id[:]         // ID
		data[i*3+1] = mockExp     // Expiration
		data[i*3+2] = mockPayload // Payload
	}
	res, err := conn.DB().ExecContext(ctx, str, data...)
	require.NoError(t, err)
	n, err := res.RowsAffected()
	require.NoError(t, err)
	require.GreaterOrEqual(t, n, int64(len(certIDs)))
}

func retrieveCertificatePayloads(
	ctx context.Context,
	t tests.T,
	conn db.Conn,
	IDs []common.SHA256Output,
) {
	if len(IDs) == 0 {
		return
	}
	str := "SELECT cert_id,payload from certs WHERE cert_id IN " +
		mysql.RepeatStmt(1, len(IDs))
	params := make([]any, len(IDs))
	for i, id := range IDs {
		params[i] = id[:]
	}
	rows, err := conn.DB().QueryContext(ctx, str, params...)
	require.NoError(t, err)

	m := make(map[common.SHA256Output][]byte, len(IDs))
	for rows.Next() {
		var id, payload []byte
		err := rows.Scan(&id, &payload)
		require.NoError(t, err)
		idArray := (*common.SHA256Output)(id)
		m[*idArray] = payload
	}
	// Sort them in the same order as the IDs.
	payloads := make([][]byte, len(IDs))
	for i, id := range IDs {
		payloads[i] = m[id]
	}
	require.Equal(t, len(IDs), len(payloads))
}

func insertIntoDirty(
	ctx context.Context,
	conn db.Conn,
	tableName string,
	domainIDs []common.SHA256Output) error {

	// Make the list of domain IDs unique.
	domainIDsSet := make(map[common.SHA256Output]struct{})
	for _, id := range domainIDs {
		domainIDsSet[id] = struct{}{}
	}

	// It fails with all of them: "REPLACE INTO", "INSERT", or "INSERT IGNORE",
	// because there is a UNIQUE constraint (key) that needs locking.
	str := fmt.Sprintf("INSERT IGNORE INTO %s (domain_id) VALUES %s",
		tableName,
		mysql.RepeatStmt(len(domainIDsSet), 1)) // 1 column
	data := make([]interface{}, len(domainIDsSet))
	i := 0
	for k := range domainIDsSet {
		k := k
		data[i] = k[:] // ID
		i++
	}
	_, err := conn.DB().ExecContext(ctx, str, data...)
	return err
}

func loadDataWithCSV(ctx context.Context, t tests.T, conn db.Conn, filepath string) {
	ctx, span := tr.T("db").Start(ctx, "from-csv")
	defer span.End()

	str := `LOAD DATA CONCURRENT INFILE ? IGNORE INTO TABLE insert_test ` +
		`FIELDS TERMINATED BY ',' ENCLOSED BY '"' LINES TERMINATED BY '\n' ` +
		`(@cert_id,expiration,@payload) SET ` +
		`cert_id = FROM_BASE64(@cert_id),` +
		`payload = FROM_BASE64(@payload);`
	_, err := conn.DB().ExecContext(ctx, str, filepath)
	require.NoError(t, err)
}

func writeCSV(
	t tests.T,
	filename string,
	records [][]string,
) {
	f, err := os.Create(filename)
	require.NoError(t, err)
	w := bufio.NewWriterSize(f, 1024*1024*1024) // 1GB buffer

	csv := csv.NewWriter(w)
	csv.WriteAll(records)
	csv.Flush()
	err = w.Flush()
	require.NoError(t, err)
	err = f.Close()
	require.NoError(t, err)
}

func writeChunkedCsv(
	t tests.T,
	fileNameFunc func(int) string,
	NWorkers int,
	records [][]string, // rows of columns
) {
	chunks := sliceSplitter(records, NWorkers)
	wg := sync.WaitGroup{}
	wg.Add(NWorkers)
	for w, chunk := range chunks {
		w := w
		chunk := chunk
		go func() {
			defer wg.Done()
			writeCSV(t, fileNameFunc(w), chunk)
			t.Logf("[%2d] wrote %d records\n", w, len(chunk))
		}()
	}
	wg.Wait()
}

// Function to split all the data in N CSV files, where each file contains
// records sorted by the result of the hasher function applied to cert_id.
func writeSortedChunkedCsv(
	ctx context.Context,
	t tests.T,
	records [][]string,
	N int,
	hasher func(*common.SHA256Output, int) uint, //  hash function that determines the partition
	fName func(int) string, //         filename function
) {
	ctx, span := tr.T("file").Start(ctx, "write-sorted-chunked-csv")
	defer span.End()

	// Require N to be positive.
	require.Greater(t, N, 0)

	_, spanSort := tr.T("file").Start(ctx, "sort-records")

	// Compute how many bits we need to cover N partitions (i.e. ceil(log2(N-1)),
	// doable by computing the bit length of N-1 even if not a power of 2.
	// deleteme use db function
	nBits := 0
	for n := N - 1; n > 0; n >>= 1 {
		nBits++
	}

	// Parse the cert ID and store everything as it was in a new type.
	type Parsed struct {
		part   uint
		fields []string
	}
	// parsed has the same size as records.
	parsed := make([]Parsed, len(records))
	for i, r := range records {
		// First column is cert_id, in base64.
		id, err := base64.StdEncoding.DecodeString(r[0])
		require.NoError(t, err)

		parsed[i].part = hasher((*common.SHA256Output)(id), nBits)
		parsed[i].fields = r
	}
	// Sort them according to cert_id.
	sort.Slice(parsed, func(i, j int) bool {
		return parsed[i].part < parsed[j].part
	})
	spanSort.End()

	// Split in N chunks. Each chunk takes all records from last index
	// until 256*w/N , 1<=w<=N .
	wg := sync.WaitGroup{}
	wg.Add(N)
	for w := 0; w < N; w++ {
		chunk := make([][]string, 0, len(parsed)) // allocate here, reuse in the loop

		// This worker takes all values corresponding to partition number `w`.
		_, spanFind := tr.T("file").Start(ctx, "find-elems-to-partition")
		for i := 0; i < len(parsed); i++ {
			r := parsed[i]

			// Find out if this worker should take the record or not.
			if r.part == uint(w) {
				chunk = append(chunk, r.fields)
			} else {
				// Jump to the next worker.
				parsed = parsed[i:]
				break
			}
		}
		spanFind.End()

		w := w
		go func() {
			defer wg.Done()
			_, span := tr.T("file").Start(ctx, "write-partition")
			defer span.End()
			tr.SetAttrInt(span, "worker-number", w)

			// We are done with this worker.
			writeCSV(t, fName(w), chunk)
			t.Logf("[%2d] wrote %d records\n", w, len(chunk))
		}()
	}
	wg.Wait()
}

func recordsFromCertIDs(
	IDs []common.SHA256Output,
	mockExp time.Time,
	mockPayload []byte,
) [][]string {

	exp := mockExp.Format(time.DateTime)
	payload := base64.StdEncoding.EncodeToString(mockPayload)

	records := make([][]string, len(IDs))
	for i, id := range IDs {
		records[i] = make([]string, 3)
		records[i][0] = base64.StdEncoding.EncodeToString(id[:])
		records[i][1] = exp
		records[i][2] = payload
	}
	return records
}

// sliceSplitter returns a slice of slices. It basically groups items given in a slice in chunks.
// The first index of chunks is the chunk, 0<=chunk<NWorkers . E.g. chunks[2] is the third chunk.
// The slice inside each chunk is the collection of items of that chunk.
func sliceSplitter[T any](collection []T, NChunks int) [][]T {
	chunker := func(chunkIni, chunkEnd int) [][]T {
		chunkSize := len(collection) / NChunks
		if chunkIni == 0 && len(collection)%NChunks != 0 {
			// Spread remainder (e.g. 32 bytes among 10 workers -> 4 bytes for 2
			// first workers, 3 for the rest).
			chunkSize = chunkSize + 1
		}
		chunks := make([][]T, 0, chunkEnd-chunkIni)
		for w := chunkIni; w < chunkEnd; w++ {
			s := w * chunkSize
			e := (w + 1) * chunkSize
			records := collection[s:e]
			chunks = append(chunks, records)
		}
		return chunks
	}
	chunks := chunker(0, len(collection)%NChunks)
	chunks = append(chunks, chunker(len(collection)%NChunks, NChunks)...)
	return chunks
}

// csvChunkFileName returns the name for a CSV file for a chunk given the worker index.
// The parameter qualifier is used to distinguish e.g. sorted files from others. It is appended
// to the base file name before the worker index and extension.
// An example of an execution:
// csvChunkFileName("/tmp/insert_test_data.csv", "sorted", 3) = "/tmp/insert_test_data-sorted.3.csv"
func csvChunkFileName(CSVFilePath, qualifier string, workerIndex int) string {
	if qualifier != "" {
		qualifier = "-" + qualifier
	}
	dir, file := filepath.Split(CSVFilePath)
	ext := filepath.Ext(file)
	file = strings.TrimSuffix(file, ext)
	file = fmt.Sprintf("%s%s.%d%s", file, qualifier, workerIndex, ext)
	return filepath.Join(dir, file)
}

// Function that removes all CSV files from 0 to N, using the naming function `nameFunc`.
func removeChunkedCsv(t tests.T, fName func(int) string, N int) {
	for w := 0; w < N; w++ {
		err := os.Remove(fName(w))
		require.NoError(t, err)
	}
}

func mockTestData(t tests.T, NCerts int) []common.SHA256Output {
	return random.RandomIDsForTest(t, NCerts)
}

// hasherMSB returns the most significant `nBits` of `id` as an int.
func hasherMSB(id *common.SHA256Output, nBits int) uint {
	return mysql.PartitionByIdMSB(id, nBits)
}

// hasherLSB returns the least significant `nBits` of `id` as an int.
func hasherLSB(id *common.SHA256Output, nBits int) uint {
	return mysql.PartitionByIdLSB(id, nBits)
}

func runWithCsvFile(
	ctx context.Context,
	t tests.T,
	conn db.Conn,
	N int, // number of chunks/partitions
	createTableFunc func(tests.T, int), // function to create the table
	fName func(int) string, // function returning chunked csv filename
) {
	ctx, span := tr.T("run-csv-file").Start(ctx, "run")
	defer span.End()

	// Create table, but with partitions.
	if createTableFunc != nil {
		createTableFunc(t, N)
	}

	tests.Run(t, "load_only", func(t tests.T) {
		// There are N files. Load them in parallel.
		wg := sync.WaitGroup{}
		wg.Add(N)
		for w := 0; w < N; w++ {
			w := w
			go func() {
				defer wg.Done()
				loadDataWithCSV(ctx, t, conn, fName(w))
			}()
		}
		wg.Wait()
	})
	removeChunkedCsv(t, fName, N)
}
