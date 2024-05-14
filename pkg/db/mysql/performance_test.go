package mysql_test

import (
	"bufio"
	"context"
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
)

// TestInsertPerformance tests the insert performance using different approaches, in articuno:
// TestInsertPerformance/MyISAM (58.31s)
// TestInsertPerformance/InnoDB (54.51s)
func TestInsertPerformance(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancelF()

	// Configure a test DB.
	config, removeF := testdb.ConfigureTestDB(t)
	defer removeF()

	// Connect to the DB.
	conn := testdb.Connect(t, config)
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
	require.Equal(t, 0, NCerts%BatchSize, "there is an error in the test setup. NCerts must be a "+
		"multiple of BatchSize, modify either of them")
	// From xenon2025h1 we have an average of 1100b/cert
	PayloadSize := 1_100
	allCertIDs := make([]*common.SHA256Output, NCerts)
	for i := 0; i < NCerts; i++ {
		allCertIDs[i] = new(common.SHA256Output)
		binary.LittleEndian.PutUint64(allCertIDs[i][:], uint64(i))
	}
	rand.Shuffle(len(allCertIDs), func(i, j int) {
		allCertIDs[i], allCertIDs[j] = allCertIDs[j], allCertIDs[i]
	})
	mockExp := time.Unix(42, 0)
	mockPayload := make([]byte, PayloadSize)
	t.Log("Mock data ready in memory")

	// Note that InnoDB works much faster with insertions with AUTO INCREMENT.
	t.Run("InnoDB", func(t *testing.T) {
		tests.SkipExpensiveTest(t)
		// Create a certs-like table using MyISAM.
		str := "DROP TABLE IF EXISTS `insert_test`"
		_, err := conn.DB().ExecContext(ctx, str)
		require.NoError(t, err)
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
		require.NoError(t, err)

		str = "ALTER INSTANCE DISABLE INNODB REDO_LOG;"
		_, err = conn.DB().ExecContext(ctx, str)
		require.NoError(t, err)

		str = "SET autocommit=0;"
		_, err = conn.DB().ExecContext(ctx, str)
		require.NoError(t, err)

		str = "SET unique_checks=0;"
		_, err = conn.DB().ExecContext(ctx, str)
		require.NoError(t, err)

		str = "START TRANSACTION"
		_, err = conn.DB().ExecContext(ctx, str)
		require.NoError(t, err)

		callFuncPerIDBatch(NWorkers, BatchSize, allCertIDs, func(workerID int, IDs []*common.SHA256Output) {
			insertCerts(ctx, t, conn, "insert_test", IDs, mockExp, mockPayload)
		})

		str = "COMMIT"
		_, err = conn.DB().ExecContext(ctx, str)
		require.NoError(t, err)

		str = "SET unique_checks=1;"
		_, err = conn.DB().ExecContext(ctx, str)
		require.NoError(t, err)

		str = "ALTER INSTANCE DISABLE INNODB REDO_LOG;"
		_, err = conn.DB().ExecContext(ctx, str)
		require.NoError(t, err)
	})

	// Create a certs-like table using MyISAM.
	// 58K certs/s using articuno.
	t.Run("MyISAM", func(t *testing.T) {
		str := "DROP TABLE IF EXISTS `insert_test`"
		_, err := conn.DB().ExecContext(ctx, str)
		require.NoError(t, err)
		str = `CREATE TABLE insert_test (
			cert_id VARBINARY(32) NOT NULL,
			expiration DATETIME NOT NULL,
			payload LONGBLOB,

			PRIMARY KEY(cert_id)
		) ENGINE=MyISAM CHARSET=binary COLLATE=binary;`
		_, err = conn.DB().ExecContext(ctx, str)
		require.NoError(t, err)

		callFuncPerIDBatch(NWorkers, BatchSize, allCertIDs, func(workerID int, IDs []*common.SHA256Output) {
			insertCerts(ctx, t, conn, "insert_test", IDs, mockExp, mockPayload)
		})
	})

	CSVFilePath := "/mnt/data/tmp/insert_test_data.csv"
	t.Run("create_data_to_csv", func(t *testing.T) {
		writeCSV(t, CSVFilePath, rowsFromCertIDs(allCertIDs, mockExp, mockPayload))
	})
	t.Run("save_table_to_csv", func(t *testing.T) {
		tests.SkipExpensiveTest(t)
		str := "DROP TABLE IF EXISTS `insert_test`"
		_, err := conn.DB().ExecContext(ctx, str)
		require.NoError(t, err)
		str = `CREATE TABLE insert_test (
			cert_id VARBINARY(32) NOT NULL,
			expiration DATETIME NOT NULL,
			payload LONGBLOB,

			PRIMARY KEY(cert_id)
		) ENGINE=MyISAM CHARSET=binary COLLATE=binary;`
		_, err = conn.DB().ExecContext(ctx, str)
		require.NoError(t, err)

		callFuncPerIDBatch(NWorkers, BatchSize, allCertIDs, func(workerID int, IDs []*common.SHA256Output) {
			insertCerts(ctx, t, conn, "insert_test", IDs, mockExp, mockPayload)
		})

		str = `SELECT TO_BASE64(cert_id),expiration,TO_BASE64(payload) FROM insert_test INTO OUTFILE ? ` +
			`FIELDS TERMINATED BY ',' ENCLOSED BY '"' ` +
			`LINES TERMINATED BY '\n'`
		_, err = conn.DB().ExecContext(ctx, str, CSVFilePath)
		require.NoError(t, err)
	})

	// Load a file directly.
	// In articuno it takes 78s, that is, 64K certs/s (file not in RAID)
	// In articuno it takes 65s, that is, 77K certs/s (file in RAID)
	t.Run("load_data_myisam", func(t *testing.T) {
		str := "DROP TABLE IF EXISTS `insert_test`"
		_, err := conn.DB().ExecContext(ctx, str)
		require.NoError(t, err)
		str = `CREATE TABLE insert_test (
			cert_id VARBINARY(32) NOT NULL,
			expiration DATETIME NOT NULL,
			payload LONGBLOB,

			PRIMARY KEY(cert_id)
		) ENGINE=MyISAM CHARSET=binary COLLATE=binary;`
		_, err = conn.DB().ExecContext(ctx, str)
		require.NoError(t, err)

		str = `LOAD DATA CONCURRENT INFILE ? IGNORE INTO TABLE insert_test ` +
			`FIELDS TERMINATED BY ',' ENCLOSED BY '"' LINES TERMINATED BY '\n' ` +
			`(@cert_id,expiration,@payload) SET ` +
			`cert_id = FROM_BASE64(@cert_id),` +
			`payload = FROM_BASE64(@payload);`
		_, err = conn.DB().ExecContext(ctx, str, CSVFilePath)
		require.NoError(t, err)
	})
}

// TestPartitionInsert tests the performance of inserting data into a certs-like table,
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

// TestPartitionInsert/load_data/innodb/parallel/range/16 (13.46s)
// TestPartitionInsert/load_data/innodb/parallel/range/32 (12.33s)
// TestPartitionInsert/load_data/innodb/parallel/range/64 (12.03s)
// TestPartitionInsert/load_data/innodb/parallel/range/sorted16 (13.46s)
// TestPartitionInsert/load_data/innodb/parallel/range/sorted32 (12.28s)
// TestPartitionInsert/load_data/innodb/parallel/range/sorted64 (12.20s)
// TestPartitionInsert/load_data/innodb/parallel/range/inverse32 (11.67s)
// TestPartitionInsert/load_data/innodb/parallel/range/inverse64 (12.00s)

// TestPartitionInsert/load_data/innodb/parallel/key/32 (11.64s)
// TestPartitionInsert/load_data/innodb/parallel/key/64 (12.47s)
// TestPartitionInsert/load_data/innodb/parallel/key/sorted32 (12.00s)
// TestPartitionInsert/load_data/innodb/parallel/key/inverse32 (11.98s)

// TestPartitionInsert/load_data/innodb/parallel/linear/32 (14.00s)
// TestPartitionInsert/load_data/innodb/parallel/linear/64 (16.70s)
// TestPartitionInsert/load_data/innodb/parallel/linear/sorted32 (16.00s)
// TestPartitionInsert/load_data/innodb/parallel/linear/sorted64 (14.78s)
// TestPartitionInsert/load_data/innodb/parallel/linear/inverse32 (11.56s)
// TestPartitionInsert/load_data/innodb/parallel/linear/inverse64 (14.02s)

// Summary:
// - The page size was extremely important.
// - Reconfiguring the RAID with an appropriate chunk of 64Kb was extremely important.
// - Inserting in parallel with InnoDB is faster than MyISAM
// - Partitioning helps performance, up to a certain number of them.
// - Sorting the entries, so that each thread always cares about the same range,
// does NOT help performance; it doesn't hurt it either.
// We can use sorting to assign IDs to different workers, to avoid
// dead-locks for large multi-inserts.

// We decide to use 32 partitions, linear key, inverse sorted data, as we anyway will be "sorting"
// (aka dispatching) the data to avoid deadlocks.
// The reason that the inverse sorted data is faster might be because each thread will attack
// many partitions, while straight sorted data means each thread uses just one.
// We could use KEY for partitions, but the data is sorted anyway.
func TestPartitionInsert(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancelF()

	// Configure a test DB.
	config, removeF := testdb.ConfigureTestDB(t)
	defer removeF()

	// Connect to the DB.
	conn := testdb.Connect(t, config)
	defer conn.Close()

	exec := func(t *testing.T, query string, args ...any) {
		exec(ctx, t, conn, query, args...)
	}

	NCerts := 5_000_000
	BatchSize := 10_000
	NWorkers := 64
	if testing.Short() {
		// Make the test much shorter, 80K certs only.
		BatchSize = 10_000
		NWorkers = 8
		NCerts = 10 * NWorkers * BatchSize
	}
	require.Equal(t, 0, NCerts%BatchSize, "there is an error in the test setup. NCerts must be a "+
		"multiple of BatchSize, modify either of them")

	CSVFilePath := "/mnt/data/tmp/insert_test_data.csv"
	t.Run("create_data_to_csv", func(t *testing.T) {
		// Create lots of data to insert into the `certs` table.
		// From xenon2025h1 we have an average of 1100b/cert
		PayloadSize := 1_100
		allCertIDs := make([]*common.SHA256Output, NCerts)
		for i := 0; i < NCerts; i++ {
			allCertIDs[i] = new(common.SHA256Output)
			// Random, valid IDs.
			copy(allCertIDs[i][:], random.RandomBytesForTest(t, 32))
		}
		// Shuffle the order of certificates.
		rand.Shuffle(len(allCertIDs), func(i, j int) {
			allCertIDs[i], allCertIDs[j] = allCertIDs[j], allCertIDs[i]
		})
		mockExp := time.Unix(42, 0)
		mockPayload := make([]byte, PayloadSize)
		t.Log("Mock data ready in memory")

		// Create the file manually.
		f, err := os.Create(CSVFilePath)
		require.NoError(t, err)
		w := bufio.NewWriterSize(f, 1024*1024*1024) // 1GB buffer
		exp := mockExp.Format(time.DateTime)
		payload := base64.StdEncoding.EncodeToString(mockPayload)
		for _, id := range allCertIDs {
			id := base64.StdEncoding.EncodeToString(id[:])
			_, err := w.WriteString(fmt.Sprintf("\"%s\",\"%s\",\"%s\"\n", id, exp, payload))
			require.NoError(t, err)
		}
		err = w.Flush()
		require.NoError(t, err)
		err = f.Close()
		require.NoError(t, err)
	})

	// Load a file directly.
	t.Run("load_data", func(t *testing.T) {
		dropTable := func(t *testing.T) {
			exec(t, "DROP TABLE IF EXISTS `insert_test`")
		}
		loadCSV := func(t *testing.T, filepath string) {
			exec(t, `LOAD DATA CONCURRENT INFILE ? IGNORE INTO TABLE insert_test `+
				`FIELDS TERMINATED BY ',' ENCLOSED BY '"' LINES TERMINATED BY '\n' `+
				`(@cert_id,expiration,@payload) SET `+
				`cert_id = FROM_BASE64(@cert_id),`+
				`payload = FROM_BASE64(@payload);`, filepath)
		}
		t.Run("myisam", func(t *testing.T) {
			dropTable(t)
			exec(t, `CREATE TABLE insert_test (
				cert_id VARBINARY(32) NOT NULL,
				parent_id VARBINARY(32) DEFAULT NULL,
				expiration DATETIME NOT NULL,
				payload LONGBLOB,
				PRIMARY KEY(cert_id)
			) ENGINE=MyISAM CHARSET=binary COLLATE=binary;`)
			loadCSV(t, CSVFilePath)
		})
		t.Run("innodb", func(t *testing.T) {
			dropTable(t)
			exec(t, `CREATE TABLE insert_test (
				auto_id BIGINT NOT NULL AUTO_INCREMENT,
				cert_id VARBINARY(32) NOT NULL,
				parent_id VARBINARY(32) DEFAULT NULL,
				expiration DATETIME NOT NULL,
				payload LONGBLOB,
				PRIMARY KEY(auto_id),
				UNIQUE KEY(cert_id)
			) ENGINE=InnoDB CHARSET=binary COLLATE=binary;`)

			t.Run("single", func(t *testing.T) {
				// For better performance with InnoDB while loading bulk data, TAL:
				// https://dev.mysql.com/doc/refman/8.3/en/optimizing-innodb-bulk-data-loading.html
				loadCSV(t, CSVFilePath)
			})
			t.Run("parallel", func(t *testing.T) {
				NWorkers := NWorkers // Use the same value

				chunkFilePath := func(workerIndex int) string {
					dir, file := filepath.Split(CSVFilePath)
					ext := filepath.Ext(file)
					file = strings.TrimSuffix(file, ext)
					file = fmt.Sprintf("%s.%d%s", file, workerIndex, ext)
					return filepath.Join(dir, file)
				}
				chunkFilePathSorted := func(workerIndex int) string {
					dir, file := filepath.Split(CSVFilePath)
					ext := filepath.Ext(file)
					file = strings.TrimSuffix(file, ext)
					file = fmt.Sprintf("%s-sorted.%d%s", file, workerIndex, ext)
					return filepath.Join(dir, file)
				}

				// Function that removes all CSV files from 0 to N, using the naming function `nameFunc`.
				removeCsvFiles := func(t *testing.T, fName func(int) string, N int) {
					// Remove leftover CSV files.
					for w := 0; w < N; w++ {
						err := os.Remove(fName(w))
						require.NoError(t, err)
					}
				}

				// Function to split all the data in N CSV files.
				splitFile := func(t *testing.T, numParts int) {
					// We have NCert records in the csv, read them all
					records := rowsFromCsvFile(t, CSVFilePath)
					require.Equal(t, NCerts, len(records))
					// Split in N chunks (spread remainder)
					writeChunkedCSV(t, chunkFilePath, numParts, records)
				}

				// Function to split all the data in N CSV files, where each file contains
				// records sorted by the result of the hasher function applied to cert_id.
				splitFileSorted := func(t *testing.T, N int, hasher func([]byte, int) uint) {
					// Require N to be positive.
					require.Greater(t, N, 0)
					// require.Equal(t, 0, N&(N-1), "expected a power of 2")
					// Compute how many bits we need to cover N partitions (i.e. ceil(log2(N-1)),
					// doable by computing the bit length of N-1 even if not a power of 2.
					nBits := 0
					for n := N - 1; n > 0; n >>= 1 {
						nBits++
					}
					// We have NCert records in the csv, read them all
					records := rowsFromCsvFile(t, CSVFilePath)
					require.Equal(t, NCerts, len(records))
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
						// parsed[i].part = uint(id[0])
						parsed[i].part = hasher(id, nBits)
						parsed[i].fields = r
					}
					// Sort them according to cert_id.
					sort.Slice(parsed, func(i, j int) bool {
						return parsed[i].part < parsed[j].part
					})

					// Split in N chunks. Each chunk takes all records from last index
					// until 256*w/N , 1<=w<=N .
					wg := sync.WaitGroup{}
					wg.Add(N)
					for w := 0; w < N; w++ {
						chunk := make([][]string, 0, len(parsed)) // allocate here, reuse in the loop

						// This worker takes all values corresponding to partition number `w`.
						// nextValue := uint(256 * w / N)
						for i := 0; i < len(parsed); i++ {
							r := parsed[i]

							// Find out if this worker should take the record or not.
							// if r.part < nextValue {
							if r.part == uint(w) {
								chunk = append(chunk, r.fields)
							} else {
								// Jump to the next worker.
								parsed = parsed[i:]
								break
							}
						}
						w := w
						go func() {
							defer wg.Done()
							// We are done with this worker.
							writeCSV(t, chunkFilePathSorted(w), chunk)
							fmt.Printf("[%2d] wrote %d records\n", w, len(chunk))
						}()
					}
					wg.Wait()
				}
				// Hash function that returns the most significant `nBits` of `id` as an int.
				hasherMSB := func(id []byte, nBits int) uint {
					return uint(id[0] >> (8 - byte(nBits)))
				}
				hasherLSB := func(id []byte, nBits int) uint {
					return uint(id[31] >> (8 - byte(nBits)))
				}

				// Function to split all the data in N CSV files, where each file contains
				// records sorted by cert_id, so that for file w all cert IDs are in the
				// range 256*w/N .
				splitFileMSBSorted := func(t *testing.T, N int) {
					splitFileSorted(t, N, hasherMSB)
				}

				splitFileLSBSorted := func(t *testing.T, N int) {
					splitFileSorted(t, N, hasherLSB)
				}

				t.Run("load_0_partitions", func(t *testing.T) {
					splitFile(t, NWorkers)
					t.Run("load_only", func(t *testing.T) {
						// There are NWorkers files. Load them in parallel.
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
					})
					removeCsvFiles(t, chunkFilePath, NWorkers)
				})
				t.Run("range", func(t *testing.T) {
					createTable := func(t *testing.T, numPartitions int) {
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

					runWithCsvFile := func(t *testing.T, N int, fName func(int) string) {
						// Recreate table, but with partitions.
						createTable(t, N)
						t.Run("load_only", func(t *testing.T) {
							// There are N files. Load them in parallel.
							wg := sync.WaitGroup{}
							wg.Add(N)
							for w := 0; w < N; w++ {
								w := w
								go func() {
									defer wg.Done()
									loadCSV(t, fName(w))
								}()
							}
							wg.Wait()
						})
						removeCsvFiles(t, fName, N)
					}

					runPartitionTest := func(t *testing.T, numPartitions int) {
						splitFile(t, numPartitions)
						runWithCsvFile(t, numPartitions, chunkFilePath)
					}
					runMsbSortedPartitionTest := func(t *testing.T, numPartitions int) {
						splitFileMSBSorted(t, numPartitions)
						runWithCsvFile(t, numPartitions, chunkFilePathSorted)
					}
					runLsbSortedPartitionTest := func(t *testing.T, numPartitions int) {
						splitFileLSBSorted(t, numPartitions)
						runWithCsvFile(t, numPartitions, chunkFilePathSorted)
					}

					t.Run("2", func(t *testing.T) {
						runPartitionTest(t, 2)
					})
					t.Run("4", func(t *testing.T) {
						runPartitionTest(t, 4)
					})
					t.Run("8", func(t *testing.T) {
						runPartitionTest(t, 8)
					})
					t.Run("16", func(t *testing.T) {
						runPartitionTest(t, 16)
					})
					t.Run("32", func(t *testing.T) {
						runPartitionTest(t, 32)
					})
					t.Run("64", func(t *testing.T) {
						runPartitionTest(t, 64)
					})
					// Sorted data tests.
					t.Run("sorted2", func(t *testing.T) {
						runMsbSortedPartitionTest(t, 2)
					})
					t.Run("sorted4", func(t *testing.T) {
						runMsbSortedPartitionTest(t, 4)
					})
					t.Run("sorted8", func(t *testing.T) {
						runMsbSortedPartitionTest(t, 8)
					})
					t.Run("sorted16", func(t *testing.T) {
						runMsbSortedPartitionTest(t, 16)
					})
					t.Run("sorted32", func(t *testing.T) {
						runMsbSortedPartitionTest(t, 32)
					})
					t.Run("sorted64", func(t *testing.T) {
						runMsbSortedPartitionTest(t, 64)
					})
					t.Run("inverse32", func(t *testing.T) {
						runLsbSortedPartitionTest(t, 32)
					})
					t.Run("inverse64", func(t *testing.T) {
						runLsbSortedPartitionTest(t, 64)
					})
				})

				t.Run("key", func(t *testing.T) {
					// Creates a table partitioned by key, linearly. The LSBs are used.
					createTable := func(t *testing.T, numPartitions int) {
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
					runWithCsvFile := func(t *testing.T, N int, fName func(int) string) {
						// Recreate table, but with partitions.
						createTable(t, N)
						t.Run("load_only", func(t *testing.T) {
							// There are N files. Load them in parallel.
							wg := sync.WaitGroup{}
							wg.Add(N)
							for w := 0; w < N; w++ {
								w := w
								go func() {
									defer wg.Done()
									loadCSV(t, fName(w))
								}()
							}
							wg.Wait()
						})
						removeCsvFiles(t, fName, N)
					}
					runPartitionTest := func(t *testing.T, numPartitions int) {
						splitFile(t, numPartitions)
						runWithCsvFile(t, numPartitions, chunkFilePath)
					}
					runLsbSortedPartitionTest := func(t *testing.T, numPartitions int) {
						splitFileLSBSorted(t, numPartitions)
						runWithCsvFile(t, numPartitions, chunkFilePathSorted)
					}
					runMsbSortedPartitionTest := func(t *testing.T, numPartitions int) {
						splitFileMSBSorted(t, numPartitions)
						runWithCsvFile(t, numPartitions, chunkFilePathSorted)
					}

					t.Run("8", func(t *testing.T) {
						runPartitionTest(t, 8)
					})
					t.Run("32", func(t *testing.T) {
						runPartitionTest(t, 32)
					})
					t.Run("64", func(t *testing.T) {
						runPartitionTest(t, 64)
					})

					t.Run("sorted32", func(t *testing.T) {
						runLsbSortedPartitionTest(t, 32)
					})
					t.Run("inverse32", func(t *testing.T) {
						runMsbSortedPartitionTest(t, 32)
					})
				})

				t.Run("linear", func(t *testing.T) {
					// Creates a table partitioned by key, linearly. The LSBs are used.
					createTable := func(t *testing.T, numPartitions int) {
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
					runWithCsvFile := func(t *testing.T, N int, fName func(int) string) {
						// Recreate table, but with partitions.
						createTable(t, N)
						t.Run("load_only", func(t *testing.T) {
							// There are N files. Load them in parallel.
							wg := sync.WaitGroup{}
							wg.Add(N)
							for w := 0; w < N; w++ {
								w := w
								go func() {
									defer wg.Done()
									loadCSV(t, fName(w))
								}()
							}
							wg.Wait()
						})
						removeCsvFiles(t, fName, N)
					}
					runPartitionTest := func(t *testing.T, numPartitions int) {
						splitFile(t, numPartitions)
						runWithCsvFile(t, numPartitions, chunkFilePath)
					}
					runLsbSortedPartitionTest := func(t *testing.T, numPartitions int) {
						splitFileLSBSorted(t, numPartitions)
						runWithCsvFile(t, numPartitions, chunkFilePathSorted)
					}
					runMsbSortedPartitionTest := func(t *testing.T, numPartitions int) {
						splitFileLSBSorted(t, numPartitions)
						runWithCsvFile(t, numPartitions, chunkFilePathSorted)
					}

					t.Run("2", func(t *testing.T) {
						runPartitionTest(t, 2)
					})
					t.Run("4", func(t *testing.T) {
						runPartitionTest(t, 4)
					})
					t.Run("8", func(t *testing.T) {
						runPartitionTest(t, 8)
					})
					t.Run("16", func(t *testing.T) {
						runPartitionTest(t, 16)
					})
					t.Run("32", func(t *testing.T) {
						runPartitionTest(t, 32)
					})
					t.Run("64", func(t *testing.T) {
						runPartitionTest(t, 64)
					})
					// Sorted data tests.
					t.Run("sorted2", func(t *testing.T) {
						runLsbSortedPartitionTest(t, 2)
					})
					t.Run("sorted4", func(t *testing.T) {
						runLsbSortedPartitionTest(t, 4)
					})
					t.Run("sorted8", func(t *testing.T) {
						runLsbSortedPartitionTest(t, 8)
					})
					t.Run("sorted16", func(t *testing.T) {
						runLsbSortedPartitionTest(t, 16)
					})
					t.Run("sorted32", func(t *testing.T) {
						runLsbSortedPartitionTest(t, 32)
					})
					t.Run("sorted64", func(t *testing.T) {
						runLsbSortedPartitionTest(t, 64)
					})
					// Inverse data tests.
					t.Run("inverse2", func(t *testing.T) {
						runMsbSortedPartitionTest(t, 2)
					})
					t.Run("inverse4", func(t *testing.T) {
						runMsbSortedPartitionTest(t, 4)
					})
					t.Run("inverse8", func(t *testing.T) {
						runMsbSortedPartitionTest(t, 8)
					})
					t.Run("inverse16", func(t *testing.T) {
						runMsbSortedPartitionTest(t, 16)
					})
					t.Run("inverse32", func(t *testing.T) {
						runMsbSortedPartitionTest(t, 32)
					})
					t.Run("inverse64", func(t *testing.T) {
						runMsbSortedPartitionTest(t, 64)
					})
				})
			})
		})
	})
}

// TestReadPerformance checks the performance that db.RetrieveCertificatePayloads will experiment.
// We will try both MyISAM and InnoDB tables, all with queries in parallel.
func TestReadPerformance(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancelF()

	// Configure a test DB.
	config, removeF := testdb.ConfigureTestDB(t)
	defer removeF()

	// Connect to the DB.
	conn := testdb.Connect(t, config)
	defer conn.Close()

	NCerts := 5_000_000
	BatchSize := 10_000
	NWorkers := 64
	if testing.Short() {
		// Make the test much shorter, 80K certs only.
		BatchSize = 10_000
		NWorkers = 8
		NCerts = 10 * NWorkers * BatchSize
	}
	require.Equal(t, 0, NCerts%BatchSize, "there is an error in the test setup. NCerts must be a "+
		"multiple of BatchSize, modify either of them")

	CSVFilePath := "/mnt/data/tmp/insert_test_data.csv"
	chunkFilePath := func(workerIndex int) string {
		return fmt.Sprintf("%s.%d", CSVFilePath, workerIndex+1)
	}
	exec := func(t *testing.T, query string, args ...any) {
		exec(ctx, t, conn, query, args...)
	}
	dropTable := func(t *testing.T) {
		exec(t, "DROP TABLE IF EXISTS `insert_test`")
	}
	loadCSV := func(t *testing.T, filepath string) {
		exec(t, `LOAD DATA CONCURRENT INFILE ? IGNORE INTO TABLE insert_test `+
			`FIELDS TERMINATED BY ',' ENCLOSED BY '"' LINES TERMINATED BY '\n' `+
			`(@cert_id,expiration,@payload) SET `+
			`cert_id = FROM_BASE64(@cert_id),`+
			`payload = FROM_BASE64(@payload);`, filepath)
	}

	allCertIDs := make([]*common.SHA256Output, NCerts)
	// Create lots of data to insert into the `certs` table.
	t.Run("create_data", func(t *testing.T) {
		// From xenon2025h1 we have an average of 1100b/cert
		PayloadSize := 1_100
		for i := 0; i < NCerts; i++ {
			allCertIDs[i] = new(common.SHA256Output)
			// Random, valid IDs.
			copy(allCertIDs[i][:], random.RandomBytesForTest(t, 32))
		}
		// Shuffle the order of certificates.
		rand.Shuffle(len(allCertIDs), func(i, j int) {
			allCertIDs[i], allCertIDs[j] = allCertIDs[j], allCertIDs[i]
		})
		mockExp := time.Unix(42, 0)
		mockPayload := make([]byte, PayloadSize)
		t.Log("Mock data ready in memory")

		records := rowsFromCertIDs(allCertIDs, mockExp, mockPayload)
		writeChunkedCSV(t, chunkFilePath, NWorkers, records)
	})

	// Function to insert data into a table.
	insertIntoTable := func(t *testing.T) {
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
	retrieve := func(t *testing.T, NWorkers int, IDs []*common.SHA256Output) {
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
				retrieveCertificatePayloads(ctx, t, conn, IDs)
			}()
		}
	}

	// Read all certificates using MyISAM. Emulate the RetrieveCertificatesPayloads function.
	t.Run("myisam", func(t *testing.T) {
		dropTable(t)
		exec(t, `CREATE TABLE insert_test (
			cert_id VARBINARY(32) NOT NULL,
			parent_id VARBINARY(32) DEFAULT NULL,
			expiration DATETIME NOT NULL,
			payload LONGBLOB,
			PRIMARY KEY(cert_id)
		) ENGINE=MyISAM CHARSET=binary COLLATE=binary;`)
		insertIntoTable(t)
		t.Run("retrieve_only", func(t *testing.T) {
			retrieve(t, 8, allCertIDs)
		})
	})
	t.Run("innodb", func(t *testing.T) {
		dropTable(t)
		exec(t, `CREATE TABLE insert_test (
			auto_id BIGINT NOT NULL AUTO_INCREMENT,
			cert_id VARBINARY(32) NOT NULL,
			parent_id VARBINARY(32) DEFAULT NULL,
			expiration DATETIME NOT NULL,
			payload LONGBLOB,
			PRIMARY KEY(auto_id),
			UNIQUE KEY(cert_id)
		) ENGINE=InnoDB CHARSET=binary COLLATE=binary;`)
		insertIntoTable(t)
		// Important: to avoid locking the same rows while reading:
		exec(t, "SET SESSION TRANSACTION ISOLATION LEVEL READ UNCOMMITTED")

		t.Run("retrieve_only", func(t *testing.T) {
			retrieve(t, 8, allCertIDs)
		})
	})
}

// TestInsertDeadlock checks that our assumption about InnoDB hitting a deadlock while inserting
// the same ID (e.g. into dirty) is still true: there will be a deadlock error.
func TestInsertDeadlock(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancelF()

	// Configure a test DB.
	config, removeF := testdb.ConfigureTestDB(t)
	defer removeF()

	// Connect to the DB.
	conn := testdb.Connect(t, config)
	defer conn.Close()

	// Create lots of data to insert into a mock `dirty` table.
	NDomains := 100_000
	allDomainIDs := make([]*common.SHA256Output, NDomains)
	for i := 0; i < NDomains; i++ {
		allDomainIDs[i] = new(common.SHA256Output)
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
			auto_id bigint NOT NULL AUTO_INCREMENT,
			domain_id varbinary(32) NOT NULL,
			PRIMARY KEY (auto_id),
			UNIQUE KEY domain_id (domain_id)
			) ENGINE=InnoDB AUTO_INCREMENT=917012 DEFAULT CHARSET=binary;`
		_, err = conn.DB().ExecContext(ctx, str)
		require.NoError(t, err)

		callFuncPerIDBatch(32, 100_000, allDomainIDs, func(workerID int, IDs []*common.SHA256Output) {
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
			auto_id bigint NOT NULL AUTO_INCREMENT,
			domain_id varbinary(32) NOT NULL,
			PRIMARY KEY (auto_id),
			UNIQUE KEY domain_id (domain_id)
			) ENGINE=InnoDB AUTO_INCREMENT=917012 DEFAULT CHARSET=binary;`
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
}

// TestMultipleTablesOrMultipleConn checks which option is better:
//  1. Use multiple temporary tables to insert, then INSERT IGNORE into the final one.
//  2. Use a MultiConn object that "dispatches" the data to be inserted to different Conn's,
//     depending on their keys/indices.
//
// For this test we will use the "certs" table as target.
func TestMultipleTablesOrMultipleConn(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), 200*time.Second)
	defer cancelF()

	// Configure a test DB.
	config, removeF := testdb.ConfigureTestDB(t)
	defer removeF()

	// Connect to the DB.
	conn := testdb.Connect(t, config)
	defer conn.Close()

	// Create lots of data to insert into the `certs` table.
	NCerts := 1_000_000
	PayloadSize := 4_000
	allCertIDs := make([]*common.SHA256Output, NCerts)
	for i := 0; i < NCerts; i++ {
		allCertIDs[i] = new(common.SHA256Output)
		binary.LittleEndian.PutUint64(allCertIDs[i][:], uint64(i))
	}
	t.Log("Mock data ready in memory")

	// Function that inserts certificates and payload.
	mockExp := time.Unix(42, 0)
	mockPayload := make([]byte, PayloadSize)

	_ = ctx
	_ = mockExp
	_ = mockPayload
}

func exec(ctx context.Context, t *testing.T, conn db.Conn, query string, args ...any) {
	_, err := conn.DB().ExecContext(ctx, query, args...)
	require.NoError(t, err)
}

func callFuncPerIDBatch(
	numWorkers int,
	batchSize int,
	IDs []*common.SHA256Output,
	theFunc func(workerID int, IDs []*common.SHA256Output),
) {

	N := len(IDs)
	ch := make(chan []*common.SHA256Output)

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
	certIDs []*common.SHA256Output,
	mockExp time.Time,
	mockPayload []byte,
) {

	str := fmt.Sprintf("REPLACE INTO %s (cert_id,expiration,payload) VALUES %s",
		tableName,
		mysql.RepeatStmt(len(certIDs), 3)) // 3 columns
	data := make([]interface{}, 3*len(certIDs))
	for i := range certIDs {
		id := *certIDs[i]
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
	IDs []*common.SHA256Output,
) {

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
		payloads[i] = m[*id]
	}
	require.Equal(t, len(IDs), len(payloads))
}

func insertIntoDirty(
	ctx context.Context,
	conn db.Conn,
	tableName string,
	domainIDs []*common.SHA256Output) error {

	// Make the list of domain IDs unique.
	domainIDsSet := make(map[common.SHA256Output]struct{})
	for _, id := range domainIDs {
		domainIDsSet[*id] = struct{}{}
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

func writeCSV(
	t *testing.T,
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

func writeChunkedCSV(
	t *testing.T,
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
			fmt.Printf("[%2d] wrote %d records\n", w, len(chunk))
		}()
	}
	wg.Wait()
}

func rowsFromCsvFile(t *testing.T, filePath string) [][]string {
	f, err := os.Open(filePath)
	require.NoError(t, err)
	r := csv.NewReader(f)
	records, err := r.ReadAll()
	require.NoError(t, err)
	err = f.Close()
	require.NoError(t, err)
	return records
}

func rowsFromCertIDs(
	IDs []*common.SHA256Output,
	mockExp time.Time,
	mockPayload []byte,
) [][]string {

	exp := `"` + mockExp.Format(time.DateTime) + `"`
	payload := `"` + base64.StdEncoding.EncodeToString(mockPayload) + `"`

	records := make([][]string, len(IDs))
	for i, id := range IDs {
		records[i] = make([]string, 3)
		records[i][0] = `"` + (base64.StdEncoding.EncodeToString(id[:])) + `"`
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
