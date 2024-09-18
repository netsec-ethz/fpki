package main

import (
	"context"
	"fmt"
	"time"

	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
)

func coalescePayloadsForDirtyDomains(ctx context.Context, conn db.Conn) {
	fmt.Printf("\n[%s] Starting coalescing payloads for modified domains ...\n",
		time.Now().Format(time.StampMilli))
	// Use NumDBWriters.
	err := updater.CoalescePayloadsForDirtyDomains(ctx, conn)
	exitIfError(err)

	fmt.Printf("\n[%s] Done coalescing.\n", time.Now().Format(time.StampMilli))
}

func updateSMT(ctx context.Context, conn db.Conn) {
	fmt.Println("\nStarting SMT update ...")
	err := updater.UpdateSMT(ctx, conn)
	exitIfError(err)

	fmt.Println("\nDone SMT update.")
}

func cleanupDirty(ctx context.Context, conn db.Conn) {
	err := conn.CleanupDirty(ctx)
	exitIfError(err)
}
