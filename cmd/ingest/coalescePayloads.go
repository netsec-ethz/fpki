package main

import (
	"context"
	"fmt"

	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
)

func CoalescePayloadsForDirtyDomains(ctx context.Context, conn db.Conn) error {
	fmt.Println("Starting coalescing payloads for modified domains ...")
	// Use NumDBWriters.
	err := updater.CoalescePayloadsForDirtyDomains(ctx, conn)
	if err != nil {
		return err
	}

	// Print message if no errors.
	fmt.Println("Done coalescing.")
	return nil
}
