package main

import (
	"database/sql"
	"fmt"
	"sync"

	"github.com/netsec-ethz/fpki/pkg/common"
)

func CoalescePayloadsForDirtyDomains(db *sql.DB) {
	// Get all dirty domain IDs.
	str := "SELECT domain_id FROM dirty"
	rows, err := db.Query(str)
	if err != nil {
		panic(fmt.Errorf("error querying dirty domains: %w", err))
	}
	domainIDs := make([]*common.SHA256Output, 0)
	for rows.Next() {
		var domainId []byte
		err = rows.Scan(&domainId)
		if err != nil {
			panic(fmt.Errorf("error scanning domain ID: %w", err))
		}
		ptr := (*common.SHA256Output)(domainId)
		domainIDs = append(domainIDs, ptr)
	}

	// Start NumDBWriters workers.
	fmt.Printf("Starting %d workers coalescing payloads for modified domains\n", NumDBWriters)
	ch := make(chan []*common.SHA256Output)
	wg := sync.WaitGroup{}
	wg.Add(NumDBWriters)
	for i := 0; i < NumDBWriters; i++ {
		go func() {
			defer wg.Done()
			for ids := range ch {
				// We receive ids as a slice of IDs. We ought to build a long slice of bytes
				// with all the bytes concatenated.
				param := make([]byte, len(ids)*common.SHA256Size)
				for i, id := range ids {
					copy(param[i*common.SHA256Size:], id[:])
				}
				// Now call the stored procedure with this parameter.
				str := "CALL calc_several_domain_payloads(?)"
				_, err := db.Exec(str, param)
				if err != nil {
					panic(fmt.Errorf("error coalescing payload for domains: %w", err))
				}
			}
		}()
	}

	// Split the dirty domain ID list in NumDBWriters
	batchSize := len(domainIDs) / NumDBWriters
	// First workers handle one more ID than the rest, to take into account also the remainder.
	for i := 0; i < len(domainIDs)%NumDBWriters; i++ {
		b := domainIDs[i*(batchSize+1) : (i+1)*(batchSize+1)]
		ch <- b
	}
	// The rest of the workers will do a batchSize-sized item.
	restOfWorkersCount := NumDBWriters - (len(domainIDs) % NumDBWriters)
	domainIDs = domainIDs[(len(domainIDs)%NumDBWriters)*(batchSize+1):]
	for i := 0; i < restOfWorkersCount; i++ {
		b := domainIDs[i*batchSize : (i+1)*batchSize]
		ch <- b
	}

	// Close the batches channel.
	close(ch)
	// And wait for all workers to finish.
	wg.Wait()

	// Remove all entries from the dirty table.
	str = "TRUNCATE dirty"
	_, err = db.Exec(str)
	if err != nil {
		panic(fmt.Errorf("error truncating dirty table: %w", err))
	}
	fmt.Println("Done coalescing.")
}
