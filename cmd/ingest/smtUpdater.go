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
}

func NewSMTUpdater(conn db.Conn, root *common.SHA256Output, cacheHeight int) *SMTUpdater {
	var rootSlice []byte
	if root != nil {
		rootSlice = root[:]
	}
	smtTrie, err := trie.NewTrie(rootSlice, common.SHA256Hash, conn)
	if err != nil {
		panic(err)
	}
	smtTrie.CacheHeightLimit = cacheHeight
	return &SMTUpdater{
		conn:    conn,
		smtTrie: smtTrie,
	}
}

func (u *SMTUpdater) Update(ctx context.Context) error {
	fmt.Println("Starting SMT updater")

	domains, err := u.conn.UpdatedDomains(ctx)
	if err != nil {
		return err
	}
	err = updater.UpdateSMTfromDomains(ctx, u.conn, u.smtTrie, domains)
	if err != nil {
		return err
	}

	// Save root value:
	err = u.conn.SaveRoot(ctx, (*common.SHA256Output)(u.smtTrie.Root))
	if err != nil {
		return err
	}
	fmt.Println("Done SMT updater.")
	return nil
}
