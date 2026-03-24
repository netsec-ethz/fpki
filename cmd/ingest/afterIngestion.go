package main

import (
	"context"
	"fmt"
	"time"

	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	tr "github.com/netsec-ethz/fpki/pkg/tracing"
)

func coalescePayloadsForDirtyDomains(ctx context.Context, conn db.Conn) error {
	ctx, span := tr.T("db").Start(ctx, "coalescing")
	defer span.End()

	fmt.Printf("\n[%s] Starting coalescing payloads for modified domains ...\n",
		time.Now().Format(time.StampMilli))
	// Use NumDBWriters.
	err := updater.CoalescePayloadsForDirtyDomains(ctx, conn)
	if err != nil {
		return err
	}

	fmt.Printf("\n[%s] Done coalescing.\n", time.Now().Format(time.StampMilli))
	return nil
}

func updateSMT(ctx context.Context, conn db.Conn) error {
	ctx, span := tr.T("db").Start(ctx, "updating-smt")
	defer span.End()

	fmt.Println("\nStarting SMT update ...")
	err := updater.UpdateSMT(ctx, conn)
	if err != nil {
		return err
	}

	fmt.Println("\nDone SMT update.")
	return nil
}

func cleanupDirty(ctx context.Context, conn db.Conn) error {
	ctx, span := tr.T("db").Start(ctx, "cleaning-dirty")
	defer span.End()

	err := conn.CleanupDirty(ctx)
	if err != nil {
		return err
	}
	return nil
}
