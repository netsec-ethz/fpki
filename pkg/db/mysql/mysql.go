package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"

	_ "github.com/go-sql-driver/mysql"
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/util"
)

const batchSize = 1000

const NumDBWorkers = 32

type mysqlDB struct {
	db *sql.DB
}

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

func (c *mysqlDB) UpdateDomains(ctx context.Context, domainIDs []*common.SHA256Output,
	domainNames []string) error {

	if len(domainIDs) == 0 {
		return nil
	}

	// Make the list of domains unique, attach the name to each unique ID.
	domainIDsSet := make(map[common.SHA256Output]string)
	for i, id := range domainIDs {
		domainIDsSet[*id] = domainNames[i]
	}

	// Insert into dirty.
	str := "REPLACE INTO dirty (domain_id) VALUES " + repeatStmt(len(domainIDsSet), 1)
	data := make([]interface{}, len(domainIDsSet))
	i := 0
	for k := range domainIDsSet {
		k := k // Because k changes during the loop, we need a local copy that doesn't.
		data[i] = k[:]
		i++
	}
	_, err := c.db.ExecContext(ctx, str, data...)
	if err != nil {
		return err
	}

	// Insert into domains.
	str = "INSERT IGNORE INTO domains (domain_id,domain_name) VALUES " +
		repeatStmt(len(domainIDsSet), 2)
	data = make([]interface{}, 2*len(domainIDsSet))
	i = 0
	for k, v := range domainIDsSet {
		k := k
		data[2*i] = k[:]
		data[2*i+1] = v
		i++
	}
	_, err = c.db.ExecContext(ctx, str, data...)

	return err
}

// RetrieveDomainEntries: Retrieve a list of key-value pairs from domain entries table
// No sql.ErrNoRows will be thrown, if some records does not exist. Check the length of result
func (c *mysqlDB) RetrieveDomainEntries(ctx context.Context, domainIDs []*common.SHA256Output,
) ([]*db.KeyValuePair, error) {

	if len(domainIDs) == 0 {
		return nil, nil
	}

	// return c.retrieveDomainEntriesParallel(ctx, domainIDs)
	return c.retrieveDomainEntriesSequential(ctx, domainIDs)
}

func (c *mysqlDB) RetrieveDomainEntriesDirtyOnes(ctx context.Context, start, end uint64,
) ([]*db.KeyValuePair, error) {
	return c.retrieveDomainEntriesInDBJoin(ctx, start, end)
}

func (c *mysqlDB) retrieveDomainEntriesInDBJoin(
	ctx context.Context,
	start, end uint64,
) ([]*db.KeyValuePair, error) {

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

// retrieveDomainEntriesParallel uses retrieveDomainEntriesSequential NumDBWorkers times to
// query the (huge) table domain_payloads values that match the passed argument.
//
// XXX(juagargi) According to the benchmarks (see BenchmarkRetrieveDomainEntries),
// this strategy is slower than running retrieveDomainEntriesSequential.
func (c *mysqlDB) retrieveDomainEntriesParallel(
	ctx context.Context,
	domainIDs []*common.SHA256Output,
) ([]*db.KeyValuePair, error) {

	// Function closure that concurrently asks to retrieve the domainsPerWorker given the IDs.
	domainsPerWorker := make([][]*db.KeyValuePair, NumDBWorkers)
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
					c.retrieveDomainEntriesSequential(ctx, domainIDs[s:e])
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
	if err := util.ErrorsCoalesce(errs); err != nil {
		return nil, err
	}

	// Place each bundle in its place.
	allDomains := make([]*db.KeyValuePair, 0, len(domainIDs))
	for _, ids := range domainsPerWorker {
		allDomains = append(allDomains, ids...)
	}

	return allDomains, nil
}

// retrieveDomainEntriesSequential is a classic SELECT x FROM y.
func (c *mysqlDB) retrieveDomainEntriesSequential(
	ctx context.Context,
	domainIDs []*common.SHA256Output,
) ([]*db.KeyValuePair, error) {

	// Retrieve the certificate and policy IDs for each domain ID.
	str := "SELECT domain_id,cert_ids,policy_ids FROM domain_payloads WHERE domain_id IN " +
		repeatStmt(1, len(domainIDs))
	params := make([]interface{}, len(domainIDs))
	for i, id := range domainIDs {
		params[i] = id[:]
	}
	rows, err := c.db.QueryContext(ctx, str, params...)
	if err != nil {
		return nil, fmt.Errorf("error obtaining payloads for domains: %w", err)
	}

	return extractDomainEntries(rows)
}

func extractDomainEntries(rows *sql.Rows) ([]*db.KeyValuePair, error) {
	pairs := make([]*db.KeyValuePair, 0)
	for rows.Next() {
		var id, certIDs, policyIDs []byte
		err := rows.Scan(&id, &certIDs, &policyIDs)
		if err != nil {
			return nil, fmt.Errorf("error scanning domain ID and its certs/policies")
		}
		// Unfold the byte streams into IDs, sort them, and fold again.
		allIDs := append(common.BytesToIDs(certIDs), common.BytesToIDs(policyIDs)...)
		pairs = append(pairs, &db.KeyValuePair{
			Key:   *(*common.SHA256Output)(id),
			Value: common.SortIDsAndGlue(allIDs),
		})
	}
	return pairs, nil
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
