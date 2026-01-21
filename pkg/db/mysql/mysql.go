package mysql

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"os"
	"strings"
	"sync"

	_ "github.com/go-sql-driver/mysql"
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/util"
)

const (
	batchSize = 1000 // deleteme remove this constant

	NumDBWorkers  = 32 // deleteme why is it here?
	NumPartitions = NumDBWorkers
	// Note on partitions:
	// The goal of using partitions in our code is to limit the number of distinct processes or
	// threads writing data simultaneously resulting in contention. When using partitions,
	// different threads can write to one table, but each thread to only one partition.
	// So a given ID will always land to the same thread.
	// This has two benefits:
	// 1. Deadlocks cannot occur, as the same row is present only in one thread.
	// 2. Efficiency improves, as the same thread always writes to the same file (partition); this
	// 	means that several threads can safely and concurrently write to the DB without locks.
)

// PartitionByIdMSB returns the most significant `nBits` of `id` as an int.
// E.g. for 4 bits (16 partitions),
// 0x00..0x0F == 0000_0000..0000_1111 -> all go to shard "0"
// 0x10..0x1F == 0001_0000..0001_1111 -> all go to shard "1"
// ...
// 0xF0..0xFF == 1111_0000..1111_1111 -> all go to shard "31"
func PartitionByIdMSB(id *common.SHA256Output, nBits int) uint {
	return uint(id[0] >> (8 - byte(nBits)))
}

// PartitionByIdLSB returns the least significant `nBits` of `id` as an int.
func PartitionByIdLSB(id *common.SHA256Output, nBits int) uint {
	return uint(id[31] >> (8 - byte(nBits)))
}

// NumBitsForPartitionCount returns the number of bits necessary to cover numPartitions
// (i.e. ceil(log2(N-1)), doable by computing the bit length of N-1 even if not a power of 2.
func NumBitsForPartitionCount(numPartitions int) int {
	nBits := 0
	for n := numPartitions - 1; n > 0; n >>= 1 {
		nBits++
	}
	return nBits
}

type mysqlDB struct {
	db *sql.DB
}

var _ db.Conn = (*mysqlDB)(nil)

// NewMysqlDB is called to create a new instance of the mysqlDB.
func NewMysqlDB(db *sql.DB) (*mysqlDB, error) {
	return &mysqlDB{
		db: db,
	}, nil
}

func (c *mysqlDB) DB() *sql.DB {
	return c.db
}

func (c *mysqlDB) Close() error {
	return c.db.Close()
}

func (c *mysqlDB) TruncateAllTables(ctx context.Context) error {
	tables := []string{
		"tree",
		"root",
		"domains",
		"certs",
		"domain_certs",
		"domain_payloads",
		"dirty",
	}
	for _, t := range tables {
		if _, err := c.db.ExecContext(ctx, fmt.Sprintf("TRUNCATE %s", t)); err != nil {
			return err
		}
	}
	return nil
}

// UpdateDomains updates the domains table.
func (c *mysqlDB) UpdateDomains(
	ctx context.Context,
	domainIDs []common.SHA256Output,
	domainNames []string,
) error {
	// return c.updateDomainsMemory(ctx, domainIDs, domainNames)
	return c.updateDomainsCSV(ctx, domainIDs, domainNames)
}

func (c *mysqlDB) InsertCsvIntoDomains(ctx context.Context, filename string) error {
	_, err := loadDomainsTableWithCSV(ctx, c.db, filename)
	return err
}

func (c *mysqlDB) updateDomainsCSV(
	ctx context.Context,
	ids []common.SHA256Output,
	domainNames []string,
) error {
	// Prepare the records for the CSV file.
	records := make([][]string, len(ids))
	for i := 0; i < len(ids); i++ {
		records[i] = make([]string, 2)
		records[i][0] = base64.StdEncoding.EncodeToString(ids[i][:])
		records[i][1] = domainNames[i]
	}

	// Create temporary file.
	tempfile, err := os.CreateTemp(TemporaryDir, "fpki-ingest-domains-*.csv")
	if err != nil {
		return fmt.Errorf("creating temporary file: %w", err)
	}
	defer os.Remove(tempfile.Name())

	// Write data to CSV file.
	if err = writeToCSV(tempfile, records); err != nil {
		return err
	}

	// Now instruct MySQL to directly ingest this file into the certs table.
	if _, err := loadDomainsTableWithCSV(ctx, c.db, tempfile.Name()); err != nil {
		return fmt.Errorf("inserting CSV \"%s\" into DB.domains: %w", tempfile.Name(), err)
	}

	return nil
}

func (c *mysqlDB) updateDomainsMemory(
	ctx context.Context,
	domainIDs []common.SHA256Output,
	domainNames []string,
) error {
	if len(domainIDs) == 0 {
		return nil
	}

	// Make the list of domains unique, attach the name to each unique ID.
	domainIDsSet := make(map[common.SHA256Output]string)
	for i, id := range domainIDs {
		domainIDsSet[id] = domainNames[i]
	}

	// Insert into domains.
	str := "INSERT IGNORE INTO domains (domain_id,domain_name) VALUES " +
		repeatStmt(len(domainIDsSet), 2)
	data := make([]interface{}, 2*len(domainIDsSet))
	i := 0
	for k, v := range domainIDsSet {
		// Because k is of type array, &k is the same through the life of the loop. That means
		// that k[:] is also the same; assigning it to a slice copies the same pointer as storage.
		k := k // Create local copy of the 32 bytes.
		data[2*i] = k[:]
		data[2*i+1] = v
		i++
	}

	if _, err := c.db.ExecContext(ctx, str, data...); err != nil {
		return fmt.Errorf("inserting domains into domains table: %w", err)
	}

	return nil
}

// RetrieveDomainEntries: Retrieve a list of key-value pairs from domain entries table
// No sql.ErrNoRows will be thrown, if some records does not exist. Check the length of result
func (c *mysqlDB) RetrieveDomainEntries(ctx context.Context, domainIDs []common.SHA256Output,
) ([]db.KeyValuePair, error) {

	if len(domainIDs) == 0 {
		return nil, nil
	}

	// return c.retrieveDomainEntriesParallel(ctx, domainIDs)
	return c.retrieveDirtyDomainEntriesSequential(ctx, domainIDs)
}

func (c *mysqlDB) RetrieveDomainEntriesDirtyOnes(ctx context.Context, start, end uint64,
) ([]db.KeyValuePair, error) {
	return c.retrieveDirtyDomainEntriesInDBJoin(ctx, start, end)
}

func (c *mysqlDB) retrieveDirtyDomainEntriesInDBJoin(
	ctx context.Context,
	start, end uint64,
) ([]db.KeyValuePair, error) {

	str := `SELECT d.domain_id,p.cert_ids,p.policy_ids
		FROM
		(SELECT domain_id FROM dirty ORDER BY domain_id LIMIT ?,? )
		AS d
		JOIN
		domain_payloads AS p
		ON d.domain_id=p.domain_id;`
	rows, err := c.db.QueryContext(ctx, str, start, end-start)
	if err != nil {
		return nil, fmt.Errorf("retrieving domain payloads from dirty[%d,%d): %w",
			start, end, err)
	}
	return extractDomainEntries(rows)
}

// retrieveDirtyDomainEntriesParallel uses retrieveDomainEntriesSequential NumDBWorkers times to
// query the (huge) table domain_payloads values that match the passed argument.
//
// XXX(juagargi) According to the benchmarks (see BenchmarkRetrieveDomainEntries),
// this strategy is slower than running retrieveDomainEntriesSequential.
func (c *mysqlDB) retrieveDirtyDomainEntriesParallel(
	ctx context.Context,
	domainIDs []common.SHA256Output,
) ([]db.KeyValuePair, error) {

	// Function closure that concurrently asks to retrieve the domainsPerWorker given the IDs.
	domainsPerWorker := make([][]db.KeyValuePair, NumDBWorkers)
	errs := make([]error, NumDBWorkers)
	wg := sync.WaitGroup{}
	bundler := func(offset, fromWorker, toWorker, blockSize int) {
		if blockSize <= 0 {
			return
		}
		for worker, lastOffset := fromWorker, offset; worker < toWorker; worker, lastOffset =
			worker+1, lastOffset+blockSize {

			worker := worker
			lastOffset := lastOffset
			wg.Add(1)
			go func() {
				defer wg.Done()
				s := lastOffset
				e := s + blockSize
				domainsPerWorker[worker], errs[worker] =
					c.retrieveDirtyDomainEntriesSequential(ctx, domainIDs[s:e])
			}()
		}
	}

	// Divide the work in NumDBWorkers bundles.
	// E.g. if we have 203 entries and 10 workers, we want the first three to process 21 entries,
	// and the remaining 7 to process 20.
	// This means there is a base bundle size of 20 (203 / 10), a bigger bundle size of 21,
	// there are 3 workers with extra work (203 % 10) and 7 with base work (10 - 3).
	L := len(domainIDs)
	workersWithExtra := L % NumDBWorkers
	bundleSize := L / NumDBWorkers
	bundleBiggerSize := bundleSize + 1

	// Call and wait until all of them are done.
	bundler(0, 0, workersWithExtra, bundleBiggerSize)
	bundler(workersWithExtra*bundleBiggerSize, workersWithExtra, NumDBWorkers, bundleSize)
	wg.Wait()

	// Are there errors?
	if err := util.ErrorsCoalesce(errs...); err != nil {
		return nil, err
	}

	// Place each bundle in its place.
	allDomains := make([]db.KeyValuePair, 0, len(domainIDs))
	for _, ids := range domainsPerWorker {
		allDomains = append(allDomains, ids...)
	}

	return allDomains, nil
}

// retrieveDirtyDomainEntriesSequential is a classic SELECT x FROM y.
func (c *mysqlDB) retrieveDirtyDomainEntriesSequential(
	ctx context.Context,
	domainIDs []common.SHA256Output,
) ([]db.KeyValuePair, error) {

	// Retrieve the certificate and policy IDs for each domain ID.
	str := "SELECT domain_id,cert_ids,policy_ids FROM domain_payloads WHERE domain_id IN " +
		repeatStmt(1, len(domainIDs))
	params := make([]interface{}, len(domainIDs))
	for i, id := range domainIDs {
		id := id
		params[i] = id[:]
	}
	rows, err := c.db.QueryContext(ctx, str, params...)
	if err != nil {
		return nil, fmt.Errorf("error obtaining payloads for domains: %w", err)
	}

	return extractDomainEntries(rows)
}

func extractDomainEntries(rows *sql.Rows) ([]db.KeyValuePair, error) {
	pairs := make([]db.KeyValuePair, 0)
	for rows.Next() {
		var id, certIDs, policyIDs []byte
		err := rows.Scan(&id, &certIDs, &policyIDs)
		if err != nil {
			return nil, fmt.Errorf("error scanning domain ID and its certs/policies")
		}
		// Unfold the byte streams into IDs, sort them, and fold again.
		allIDs := append(common.BytesToIDs(certIDs), common.BytesToIDs(policyIDs)...)
		pairs = append(pairs, db.KeyValuePair{
			Key:   *(*common.SHA256Output)(id),
			Value: common.SortIDsAndGlue(allIDs),
		})
	}
	return pairs, nil
}

func loadDomainsTableWithCSV(
	ctx context.Context,
	db *sql.DB,
	filepath string,
) (sql.Result, error) {

	// Set read permissions to all.
	if err := os.Chmod(filepath, 0644); err != nil {
		return nil, fmt.Errorf("setting permissions to file \"%s\": %w", filepath, err)
	}

	str := `LOAD DATA CONCURRENT INFILE ? IGNORE INTO TABLE domains ` +
		`FIELDS TERMINATED BY ',' ENCLOSED BY '"' LINES TERMINATED BY '\n' ` +
		`(@domain_id,domain_name) SET ` +
		`domain_id = FROM_BASE64(@domain_id);`
	return db.ExecContext(ctx, str, filepath)
}

func writeToCSV(
	f *os.File,
	records [][]string,
) error {

	errFcn := func(err error) error {
		return fmt.Errorf("writing CSV file: %w", err)
	}

	w := bufio.NewWriterSize(f, CsvBufferSize)
	csv := csv.NewWriter(w)

	csv.WriteAll(records)
	csv.Flush()

	if err := w.Flush(); err != nil {
		return errFcn(err)
	}
	if err := f.Close(); err != nil {
		return errFcn(err)
	}

	return nil
}

// repeatStmt returns  ( (?,..dimensions..,?), ...elemCount...  )
// Use it like repeatStmt(1, len(IDs)) to obtain (?,?,...)
func repeatStmt(elemCount int, dimensions int) string {
	components := make([]string, dimensions)
	for i := 0; i < len(components); i++ {
		components[i] = "?"
	}
	toRepeat := "(" + strings.Join(components, ",") + ")"
	return strings.Repeat(toRepeat+",", elemCount-1) + toRepeat
}
