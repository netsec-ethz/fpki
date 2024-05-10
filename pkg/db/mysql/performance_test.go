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

	CSVFilePath := "/mnt/data/tmp/insert_test_data.dat"
	t.Run("create_data_to_csv", func(t *testing.T) {
		// Create the file manually.
		f, err := os.Create(CSVFilePath)
		require.NoError(t, err)
		w := bufio.NewWriterSize(f, 1024*1024*1024) // 1GB buffer
		// w := bufio.NewWriter(f)
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
// TestPartitionInsert/load_data/innodb/parallel/partitioned/16 (13.46s)
// TestPartitionInsert/load_data/innodb/parallel/partitioned/32 (12.33s)
// TestPartitionInsert/load_data/innodb/parallel/partitioned/64 (11.96s)
// TestPartitionInsert/load_data/innodb/parallel/partitioned/sorted16 (13.46s)
// TestPartitionInsert/load_data/innodb/parallel/partitioned/sorted32 (11.28s)
// TestPartitionInsert/load_data/innodb/parallel/partitioned/sorted64 (11.57s)
//
// Summary:
// - The page size was extremely important.
// - Reconfiguring the RAID with an appropriate chunk of 64Kb was extremely important.
// - Inserting in parallel with InnoDB is faster than MyISAM
// - Partitioning does not hurt, even with a large number of them.
// - Sorting the entries, so that each thread always cares about the same range, helps performance
// by a very small amount. We can use sorting to assign IDs to different workers, to avoid
// dead-locks for large multi-inserts.
//
// We decide to use 32 partitions, sorted data, as there is not much benefit going
// higher number of partitions than that.
func TestPartitionInsert(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancelF()

	// Configure a test DB.
	config, removeF := testdb.ConfigureTestDB(t)
	defer removeF()

	// Connect to the DB.
	conn := testdb.Connect(t, config)
	defer conn.Close()

	exec := func(t *testing.T, query string, args ...any) {
		_, err := conn.DB().ExecContext(ctx, query, args...)
		require.NoError(t, err)
	}

	// NCerts := 10_000_000
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

	CSVFilePath := "/mnt/data/tmp/insert_test_data.dat"
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
				// // Before loading the CSV, disable keys.
				// For better performance with InnoDB while loading bulk data, TAL:
				// https://dev.mysql.com/doc/refman/8.3/en/optimizing-innodb-bulk-data-loading.html
				loadCSV(t, CSVFilePath)
			})
			t.Run("parallel", func(t *testing.T) {
				NWorkers := NWorkers // Use the same value
				chunkFilePath := func(workerIndex int) string {
					return fmt.Sprintf("%s.%d", CSVFilePath, workerIndex+1)
				}
				chunkFilePathSorted := func(workerIndex int) string {
					return fmt.Sprintf("%s.sorted.%d", CSVFilePath, workerIndex+1)
				}

				// Function to split all the data in N CSV files.
				splitFile := func(t *testing.T, N int) {
					// We have NCert records in the csv, read them all
					f, err := os.Open(CSVFilePath)
					require.NoError(t, err)
					defer f.Close()
					r := csv.NewReader(f)
					records, err := r.ReadAll()
					require.NoError(t, err)
					require.Equal(t, NCerts, len(records))
					// Split in N chunks (spread remainder)
					chunkSize := NCerts / N
					createChunksFunc := func(begin, end int) {
						chunkSize := chunkSize
						if begin == 0 && NCerts%N != 0 {
							// Spread remainder (e.g. 32 bytes among 10 workers -> 4 bytes for 2
							// first workers, 3 for the rest).
							chunkSize = chunkSize + 1
						}
						for w := begin; w < end; w++ {
							s := w * chunkSize
							e := (w + 1) * chunkSize
							records := records[s:e]

							chunkFile, err := os.Create(chunkFilePath(w))
							require.NoError(t, err)
							chunkWriter := csv.NewWriter(chunkFile)
							err = chunkWriter.WriteAll(records)
							fmt.Printf("[%2d] wrote %d records\n", w, len(records))
							require.NoError(t, err)
							chunkWriter.Flush()
							err = chunkFile.Close()
							require.NoError(t, err)
						}
					}
					createChunksFunc(0, NCerts%N)
					createChunksFunc(NCerts%N, N)
				}

				// Function to split all the data in N CSV files, where each file contains
				// records sorted by cert_id, so that for file w all cert IDs are in the
				// range 256*w/N .
				splitFileSorted := func(t *testing.T, N int) {
					// We have NCert records in the csv, read them all
					f, err := os.Open(CSVFilePath)
					require.NoError(t, err)
					defer f.Close()
					r := csv.NewReader(f)
					records, err := r.ReadAll()
					require.NoError(t, err)
					require.Equal(t, NCerts, len(records))
					// Parse the cert ID and store everything as it was in a new type.
					type Parsed struct {
						id     uint
						fields []string
					}
					// parsed has the same size as records.
					parsed := make([]Parsed, len(records))
					for i, r := range records {
						// First column is cert_id, in base64.
						id, err := base64.StdEncoding.DecodeString(r[0])
						require.NoError(t, err)
						parsed[i].id = uint(id[0])
						parsed[i].fields = r
					}
					// Sort them according to cert_id.
					sort.Slice(parsed, func(i, j int) bool {
						return parsed[i].id < parsed[j].id
					})

					// Split in N chunks. Each chunk takes all records from last index
					// until 256*w/N , 1<=w<=N .
					for w := 1; w <= N; w++ {
						chunkFile, err := os.Create(chunkFilePathSorted(w - 1))
						require.NoError(t, err)
						chunkWriter := csv.NewWriter(chunkFile)
						// This worker takes all values if less than nextValue.
						nextValue := uint(256 * w / N)
						for i := 0; i < len(parsed); i++ {
							r := parsed[i]

							// Find out if this worker should take the record or not.
							if r.id < nextValue {
								err = chunkWriter.Write(r.fields)
								require.NoError(t, err)
							} else {
								// Report progress.
								fmt.Printf("[%2d] wrote %d records [:%d]\n", w, i, nextValue)
								// Jump to the next worker.
								parsed = parsed[i:]
								break
							}
						}
						// We are done with this worker.
						chunkWriter.Flush()
						err = chunkFile.Close()
						require.NoError(t, err)
					}
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
					// Remove leftover CSV files.
					for w := 0; w < NWorkers; w++ {
						err := os.Remove(chunkFilePath(w))
						require.NoError(t, err)
					}
				})
				t.Run("partitioned", func(t *testing.T) {
					createTable := func(t *testing.T, numPartitions int) {
						str := "CREATE TABLE insert_test ( " +
							"cert_id VARBINARY(32) NOT NULL," +
							"parent_id VARBINARY(32) DEFAULT NULL," +
							"expiration DATETIME NOT NULL," +
							"payload LONGBLOB," +
							"PRIMARY KEY(cert_id)" +
							") ENGINE=InnoDB CHARSET=binary COLLATE=binary " +
							"partition by range columns (cert_id) (\n" + "%s" + "\n);"

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
							fmt.Sprintf("partition p%d values less than (maxvalue)", numPartitions-1)
						str = fmt.Sprintf(str, strings.Join(perPartition, ",\n"))

						fmt.Printf("%s\n\n", str) // deleteme

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
						// Remove leftover CSV files.
						for w := 0; w < N; w++ {
							err := os.Remove(fName(w))
							require.NoError(t, err)
						}
					}

					runPartitionTest := func(t *testing.T, numPartitions int) {
						splitFile(t, numPartitions)
						runWithCsvFile(t, numPartitions, chunkFilePath)
					}
					runSortedPartitionTest := func(t *testing.T, numPartitions int) {
						splitFileSorted(t, numPartitions)
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
					t.Run("sorted8", func(t *testing.T) {
						runSortedPartitionTest(t, 8)
					})
					t.Run("sorted16", func(t *testing.T) {
						runSortedPartitionTest(t, 16)
					})
					t.Run("sorted32", func(t *testing.T) {
						runSortedPartitionTest(t, 32)
					})
					t.Run("sorted64", func(t *testing.T) {
						runSortedPartitionTest(t, 64)
					})
				})
			})
		})
	})
}

func TestReadPerformance(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancelF()

	// Configure a test DB.
	config, removeF := testdb.ConfigureTestDB(t)
	defer removeF()

	// Connect to the DB.
	conn := testdb.Connect(t, config)
	defer conn.Close()

	// Create lots of data to insert into the `certs` table.
	NCerts := 1_000_000
	NWorkers := 10
	require.Equal(t, 0, NCerts%NWorkers, "there is an error in the test setup. NCerts must be a "+
		"multiple of NWorkers, modify either of them")
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

	// Create a certs table using MyISAM.
	t.Run("insert_data_myisam", func(t *testing.T) {
		str := "DROP TABLE IF EXISTS `read_test`"
		_, err := conn.DB().ExecContext(ctx, str)
		require.NoError(t, err)
		str = `CREATE TABLE read_test (
				cert_id VARBINARY(32) NOT NULL,
				expiration DATETIME NOT NULL,
				payload LONGBLOB,

				PRIMARY KEY(cert_id)
			) ENGINE=MyISAM CHARSET=binary COLLATE=binary;`
		_, err = conn.DB().ExecContext(ctx, str)
		require.NoError(t, err)

		callFuncPerIDBatch(32, 2000, allCertIDs, func(workerID int, IDs []*common.SHA256Output) {
			insertCerts(ctx, t, conn, "read_test", IDs, mockExp, mockPayload)
		})
	})

	// Read all certificates using MyISAM. Emulate the RetrieveCertificatesPayloads function.
	t.Run("read_MyISAM", func(t *testing.T) {
		callFuncPerIDBatch(32, NCerts/NWorkers, allCertIDs, func(workerID int, IDs []*common.SHA256Output) {
			retrieveCertificatePayloads(ctx, t, conn, IDs)
		})
	})
	// t.Run("convert_table", func(t *testing.T) {
	// 	str := "ALTER TABLE read_test ENGINE=InnoDB"
	// 	_, err := conn.DB().ExecContext(ctx, str)
	// 	require.NoError(t, err)
	// })
	t.Run("insert_data_innodb", func(t *testing.T) {
		str := "DROP TABLE IF EXISTS `read_test`"
		_, err := conn.DB().ExecContext(ctx, str)
		require.NoError(t, err)
		str = `CREATE TABLE read_test (
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

		str = "SET autocommit=0"
		_, err = conn.DB().ExecContext(ctx, str)
		require.NoError(t, err)

		str = "START TRANSACTION"
		_, err = conn.DB().ExecContext(ctx, str)
		require.NoError(t, err)

		callFuncPerIDBatch(32, 2000, allCertIDs, func(workerID int, IDs []*common.SHA256Output) {
			insertCerts(ctx, t, conn, "read_test", IDs, mockExp, mockPayload)
		})

		str = "COMMIT"
		_, err = conn.DB().ExecContext(ctx, str)
		require.NoError(t, err)
	})
	t.Run("read_InnoDB", func(t *testing.T) {
		callFuncPerIDBatch(32, NCerts/NWorkers, allCertIDs, func(workerID int, IDs []*common.SHA256Output) {
			retrieveCertificatePayloads(ctx, t, conn, IDs)
		})
	})
}

func TestInsertDirtyInnoDB(t *testing.T) {
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
