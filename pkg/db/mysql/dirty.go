package mysql

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/util"
)

const (
	dirtyCoalesceChunkSize = 20000
	dirtyCoalesceStatsFreq = 5 * time.Second
)

func (c *mysqlDB) DirtyCount(ctx context.Context) (uint64, error) {
	counts := make([]uint64, NumPartitions)
	errs := make([]error, NumPartitions)

	var wg sync.WaitGroup
	wg.Add(NumPartitions)
	for partition := range NumPartitions {
		go func(partition int) {
			defer wg.Done()

			str := fmt.Sprintf("SELECT COUNT(*) FROM dirty PARTITION(p%d)", partition)
			row := c.db.QueryRowContext(ctx, str)
			if err := row.Err(); err != nil {
				errs[partition] = fmt.Errorf("querying dirty partition %d count: %w", partition, err)
				return
			}

			if err := row.Scan(&counts[partition]); err != nil {
				errs[partition] = fmt.Errorf("scanning dirty partition %d count: %w", partition, err)
			}
		}(partition)
	}
	wg.Wait()

	if err := util.ErrorsCoalesce(errs...); err != nil {
		return 0, fmt.Errorf("error querying dirty domains count: %w", err)
	}

	var total uint64
	for _, count := range counts {
		total += count
	}
	return total, nil
}

// RetrieveDirtyDomains returns the domain IDs that are still dirty, i.e. modified certificates for
// that domain, but not yet coalesced and ingested by the SMT.
func (c *mysqlDB) RetrieveDirtyDomains(ctx context.Context) ([]common.SHA256Output, error) {
	str := "SELECT domain_id FROM dirty"
	rows, err := c.db.QueryContext(ctx, str)
	if err != nil {
		return nil, fmt.Errorf("error querying dirty domains: %w", err)
	}
	domainIDs := make([]common.SHA256Output, 0)
	for rows.Next() {
		var domainId []byte
		err = rows.Scan(&domainId)
		if err != nil {
			return nil, fmt.Errorf("error scanning domain ID: %w", err)
		}
		domainIDs = append(domainIDs, common.SHA256Output(domainId))
	}
	return domainIDs, nil
}

func (c *mysqlDB) InsertDomainsIntoDirty(
	ctx context.Context,
	domainIDs []common.SHA256Output,
) error {
	return c.insertDomainsIntoDirtyCSV(ctx, domainIDs)
}

func (c *mysqlDB) InsertCsvIntoDirty(ctx context.Context, filename string) error {
	_, err := loadDirtyTableWithCSV(ctx, c.db, filename)
	return err
}

func (c *mysqlDB) insertDomainsIntoDirtyCSV(
	ctx context.Context,
	domainIDs []common.SHA256Output,
) error {
	// Prepare the records for the CSV file.
	records := make([][]string, len(domainIDs))
	for i := 0; i < len(domainIDs); i++ {
		records[i] = make([]string, 1)
		records[i][0] = base64.StdEncoding.EncodeToString(domainIDs[i][:])
	}

	// Create temporary file.
	tempfile, err := os.CreateTemp(TemporaryDir, "fpki-ingest-dirty-*.csv")
	if err != nil {
		return fmt.Errorf("creating temporary file: %w", err)
	}
	defer os.Remove(tempfile.Name())

	// Write data to CSV file.
	if err = writeToCSV(tempfile, records); err != nil {
		return err
	}

	// Now instruct MySQL to directly ingest this file into the certs table.
	if _, err := loadDirtyTableWithCSV(ctx, c.db, tempfile.Name()); err != nil {
		return fmt.Errorf("inserting CSV \"%s\" into DB.dirty: %w", tempfile.Name(), err)
	}

	return nil
}

func (c *mysqlDB) insertDomainsIntoDirtyMemory(
	ctx context.Context,
	domainIDs []common.SHA256Output,
) error {
	// Make the list of domains unique, attach the name to each unique ID.
	domainIDsSet := make(map[common.SHA256Output]struct{})
	for _, id := range domainIDs {
		domainIDsSet[id] = struct{}{}
	}

	str := "REPLACE INTO dirty (domain_id, coalesced) VALUES " + repeatStmt(len(domainIDsSet), 2)
	data := make([]any, 2*len(domainIDsSet))
	i := 0
	for k := range domainIDsSet {
		// Copy the 32 bytes locally here, not just the pointer or slice.
		// The loop variable k is set with 32 new bytes on each iteration, but its pointer &k does
		// not change and remains constant for all the loop ("captured"). A slice on that array
		// such as k[:] will create a new slice, with all the same storage across all iterations.
		localK := k // Because k changes during the loop, we need a local copy that doesn't.
		data[2*i] = localK[:]
		data[2*i+1] = false
		i++
	}

	if _, err := c.db.ExecContext(ctx, str, data...); err != nil {
		return fmt.Errorf("inserting domains into dirty: %w", err)
	}

	return nil
}

func (c *mysqlDB) CleanupDirty(ctx context.Context) error {
	// Remove all entries from the dirty table.
	str := "TRUNCATE dirty"
	_, err := c.db.ExecContext(ctx, str)
	if err != nil {
		return fmt.Errorf("error truncating dirty table: %w", err)
	}
	return nil
}

type dirtyCoalesceProgress struct {
	processedRows     atomic.Int64
	pendingPartitions atomic.Int64
}

// RecomputeDirtyDomainsCertAndPolicyIDs spawns NumPartitions (typically 32) goroutines.
// Each worker repeatedly coalesces one chunk for its partition until the stored procedure
// reports that there are no more pending dirty rows in that partition.
func (c *mysqlDB) RecomputeDirtyDomainsCertAndPolicyIDs(ctx context.Context) error {
	totalDirtyCount, err := c.DirtyCount(ctx)
	if err != nil {
		return fmt.Errorf("querying dirty domains before coalescing: %w", err)
	}
	if totalDirtyCount == 0 {
		return nil
	}

	errs := make([]error, NumPartitions)
	progress := &dirtyCoalesceProgress{}
	progress.pendingPartitions.Store(NumPartitions)
	doneLogging := make(chan struct{})
	defer close(doneLogging)
	go func() {
		ticker := time.NewTicker(dirtyCoalesceStatsFreq)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				fmt.Printf(
					"coalescing progress [%s]: pending partitions=%2d total dirty=%d processed=%d\n",
					time.Now().Format(time.Stamp),
					progress.pendingPartitions.Load(),
					totalDirtyCount,
					progress.processedRows.Load(),
				)
			case <-doneLogging:
				return
			}
		}
	}()
	wg := sync.WaitGroup{}
	wg.Add(NumPartitions)
	for i := range NumPartitions {
		go func(partition int) {
			defer wg.Done()
			defer func() {
				progress.pendingPartitions.Add(-1)
			}()

			conn, err := c.db.Conn(ctx)
			if err != nil {
				errs[partition] = fmt.Errorf("creating DB connection for partition %d: %w", partition, err)
				return
			}
			defer conn.Close()

			partitionProcessed := int64(0)
			for {
				chunkRows, err := callCalcDirtyDomains(ctx, conn, partition, dirtyCoalesceChunkSize)
				if err != nil {
					errs[partition] = fmt.Errorf(
						"coalescing dirty domains in partition %d: %w",
						partition,
						err,
					)
					return
				}
				if chunkRows == 0 {
					fmt.Printf(
						"\ndirty coalescing finished [%s]: partition=%d processed=%d\n",
						time.Now().Format(time.Stamp),
						partition,
						partitionProcessed,
					)
					return
				}

				partitionProcessed += chunkRows
				progress.processedRows.Add(chunkRows)
				// fmt.Printf(
				// 	"dirty coalescing chunk [%s]: partition=%d chunk=%d partition_processed=%d total_processed=%d pending_partitions=%d\n",
				// 	time.Now().Format(time.Stamp),
				// 	partition,
				// 	chunkRows,
				// 	partitionProcessed,
				// 	totalProcessed,
				// 	progress.pendingPartitions.Load(),
				// )
			}
		}(i)
	}
	wg.Wait()

	err = util.ErrorsCoalesce(errs...)
	if err != nil {
		return fmt.Errorf("coalescing dirty-domain payloads: %w", err)
	}

	return nil
}

func callCalcDirtyDomains(
	ctx context.Context,
	conn *sql.Conn,
	partition int,
	chunkSize int,
) (int64, error) {
	if _, err := conn.ExecContext(
		ctx,
		"CALL calc_dirty_domains(?, ?, @processed_rows)",
		partition,
		chunkSize,
	); err != nil {
		return 0, err
	}

	var processedRows int64
	if err := conn.QueryRowContext(ctx, "SELECT @processed_rows").Scan(&processedRows); err != nil {
		return 0, fmt.Errorf("reading processed rows for partition %d: %w", partition, err)
	}
	return processedRows, nil
}

func loadDirtyTableWithCSV(
	ctx context.Context,
	db *sql.DB,
	filepath string,
) (sql.Result, error) {

	// Set read permissions to all.
	if err := os.Chmod(filepath, 0644); err != nil {
		return nil, fmt.Errorf("setting permissions to file \"%s\": %w", filepath, err)
	}

	str := `LOAD DATA CONCURRENT INFILE ? REPLACE INTO TABLE dirty ` +
		`FIELDS TERMINATED BY ',' ENCLOSED BY '"' LINES TERMINATED BY '\n' ` +
		`(@domain_id) SET ` +
		`domain_id = FROM_BASE64(@domain_id), ` +
		`coalesced = FALSE;`
	return db.ExecContext(ctx, str, filepath)
}
