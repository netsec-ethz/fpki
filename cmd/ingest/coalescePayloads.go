package main

import (
	"context"
	"fmt"
	"sync"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
)

func CoalescePayloadsForDirtyDomains(ctx context.Context, conn db.Conn) {
	// Get all dirty domain IDs.
	domainIDs, err := conn.UpdatedDomains(ctx)
	if err != nil {
		panic(err)
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
				_, err := conn.DB().Exec(str, param)
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

	fmt.Println("Done coalescing.")
}
