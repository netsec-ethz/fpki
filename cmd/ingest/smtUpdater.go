package main

import (
	"context"
	"fmt"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
)

type SMTUpdater struct {
	conn    db.Conn
	smtTrie *trie.Trie

	errorCh chan error
	doneCh  chan error // Will have just one entry when all the processing is done
}

func NewSMTUpdater(conn db.Conn, root *common.SHA256Output, cacheHeight int) *SMTUpdater {
	var rootSlice []byte
	if root != nil {
		rootSlice = (*root)[:]
	}
	smtTrie, err := trie.NewTrie(rootSlice, common.SHA256Hash, conn)
	if err != nil {
		panic(err)
	}
	smtTrie.CacheHeightLimit = cacheHeight
	return &SMTUpdater{
		conn:    conn,
		smtTrie: smtTrie,
		errorCh: make(chan error),
		doneCh:  make(chan error),
	}
}

func (u *SMTUpdater) Start(ctx context.Context) {
	fmt.Println("Starting SMT updater")

	// Start processing the error channel.
	go u.processErrorChannel()

	// Read batches of updated nodes from `updates`:
	go func() {
		// This is the last and only processing function. After it finishes, there is nothing
		// else to process, close error channel on exiting.
		defer close(u.errorCh)

		domains, err := u.conn.UpdatedDomains(ctx)
		if err != nil {
			u.errorCh <- err
			return
		}
		u.processBatch(ctx, domains)

		// Save root value:
		err = u.conn.SaveRoot(ctx, (*common.SHA256Output)(u.smtTrie.Root))
		if err != nil {
			u.errorCh <- err
			return
		}
		fmt.Println("Done SMT updater.")
	}()
}

func (u *SMTUpdater) Wait() error {
	return <-u.doneCh
}

func (u *SMTUpdater) processErrorChannel() {
	var withErrors bool
	for err := range u.errorCh {
		if err != nil {
			withErrors = true
			fmt.Printf("SMT update, error: %s\n", err)
		}
	}
	if withErrors {
		u.doneCh <- fmt.Errorf("errors found")
	} else {
		u.doneCh <- nil
	}
	close(u.doneCh)
}

func (u *SMTUpdater) processBatch(ctx context.Context, batch []*common.SHA256Output) {
	// Read those certificates:
	entries, err := u.conn.RetrieveDomainEntries(ctx, batch)
	if err != nil {
		u.errorCh <- err
		return
	}
	keys, values, err := updater.KeyValuePairToSMTInput(entries)
	if err != nil {
		u.errorCh <- err
		return
	}

	// Update the tree.
	_, err = u.smtTrie.Update(context.Background(), keys, values)
	if err != nil {
		u.errorCh <- err
		return
	}
	// And update the tree in the DB.
	err = u.smtTrie.Commit(context.Background())
	if err != nil {
		u.errorCh <- err
		return
	}
}
