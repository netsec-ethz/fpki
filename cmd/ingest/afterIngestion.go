package main

import (
	"context"
	"fmt"

	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
)

func coalescePayloadsForDirtyDomains(ctx context.Context, conn db.Conn) {
	fmt.Println("Starting coalescing payloads for modified domains ...")
	// Use NumDBWriters.
	err := updater.CoalescePayloadsForDirtyDomains(ctx, conn)
	exitIfError(err)

	fmt.Println("Done coalescing.")
}

func updateSMT(ctx context.Context, conn db.Conn) {
	fmt.Println("Starting SMT update ...")
	err := updater.UpdateSMT(ctx, conn)
	exitIfError(err)

	fmt.Println("Done SMT update.")
}

func cleanupDirty(ctx context.Context, conn db.Conn) {
	err := conn.CleanupDirty(ctx)
	exitIfError(err)
}
