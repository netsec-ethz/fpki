package main

import (
	"context"
	"fmt"
	"sync"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
)

type SMTUpdater struct {
	Store   db.Conn
	smtTrie *trie.Trie

	errorCh chan error
	doneCh  chan error // Will have just one entry when all the processing is done
}

func NewSMTUpdater(conn db.Conn, root []byte, cacheHeight int) *SMTUpdater {
	smtTrie, err := trie.NewTrie(root, common.SHA256Hash, conn)
	if err != nil {
		panic(err)
	}
	smtTrie.CacheHeightLimit = cacheHeight
	return &SMTUpdater{
		Store:   conn,
		smtTrie: smtTrie,
		errorCh: make(chan error),
		doneCh:  make(chan error),
	}
}

func (u *SMTUpdater) Start() {
	fmt.Println("deleteme starting SMT updater")
	// Read batches of updated nodes from `updates`:
	go func() {
		domainsCh, errorCh := u.Store.UpdatedDomains()
		wg := sync.WaitGroup{}
		for batch := range domainsCh {
			// Process the batches concurrently.
			batch := batch
			wg.Add(1)
			go func() {
				defer wg.Done()
				u.processBatch(batch)
			}()
		}
		for err := range errorCh {
			u.errorCh <- err
		}
		wg.Wait()

		// Nothing else to process, close error channel.
		close(u.errorCh)
	}()
	go u.processErrorChannel()
}

func (u *SMTUpdater) Wait() error {
	fmt.Println("deleteme waiting for SMT updater to finish")
	return <-u.doneCh
}

func (u *SMTUpdater) processErrorChannel() {
	var withErrors bool
	for err := range u.errorCh {
		if err == nil {
			continue
		}
		withErrors = true
		fmt.Printf("SMT update, error: %s\n", err)
	}
	if withErrors {
		fmt.Println("deleteme errors found")
		u.doneCh <- fmt.Errorf("errors found")
	} else {
		u.doneCh <- nil
	}
	close(u.doneCh)
}

func (u *SMTUpdater) processBatch(batch []common.SHA256Output) {
	// Read those certificates:
	entries, err := u.Store.RetrieveDomainEntries(context.Background(), batch)
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
	fmt.Printf("deleteme SMT processed batch of %d elements\n", len(batch))
}
