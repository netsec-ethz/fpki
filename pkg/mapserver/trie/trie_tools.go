/**
 *  @file
 *  @copyright defined in aergo/LICENSE.txt
 */

package trie

import (
	"bytes"
	"context"
	"fmt"
)

// LoadCache loads the first layers of the merkle tree given a root
// This is called after a node restarts so that it doesn't become slow with db reads
// LoadCache also updates the Root with the given root.
func (s *Trie) LoadCache(ctx context.Context, root []byte) error {
	if s.db.Store == nil {
		return fmt.Errorf("DB not connected to trie")
	}
	s.db.liveCache = make(map[Hash][][]byte)
	ch := make(chan error, 1)
	s.loadCache(ctx, root, nil, 0, s.TrieHeight, ch)
	s.Root = root
	return <-ch
}

// loadCache loads the first layers of the merkle tree given a root
func (s *Trie) loadCache(ctx context.Context, root []byte, batch [][]byte, iBatch, height int, ch chan<- (error)) {
	if height < s.CacheHeightLimit || len(root) == 0 {
		ch <- nil
		return
	}
	if height%4 == 0 {
		// Load the node from db
		value, err := s.db.getValue(ctx, root[:HashLength])
		if err != nil {
			ch <- fmt.Errorf("the trie node %x is unavailable in the disk db, db may be corrupted | %w", root, err)
			return
		}
		batch = parseBatch(value)

		//Store node in cache.
		var node Hash = *(*[32]byte)(root) // cast root to [32]byte
		s.db.liveMux.Lock()
		s.db.liveCache[node] = batch
		s.db.liveMux.Unlock()

		iBatch = 0
		if batch[0][0] == 1 {
			// if height == 0 this will also return
			ch <- nil
			return
		}
	}
	if iBatch != 0 && batch[iBatch][HashLength] == 1 {
		// Check if node is a leaf node
		ch <- nil
	} else {
		// Load subtree
		lnode, rnode := batch[2*iBatch+1], batch[2*iBatch+2]

		lch := make(chan error, 1)
		rch := make(chan error, 1)
		go s.loadCache(ctx, lnode, batch, 2*iBatch+1, height-1, lch)
		go s.loadCache(ctx, rnode, batch, 2*iBatch+2, height-1, rch)
		if err := <-lch; err != nil {
			ch <- err
			return
		}
		if err := <-rch; err != nil {
			ch <- err
			return
		}
		ch <- nil
	}
}

// Get fetches the value of a key by going down the current trie root.
func (s *Trie) Get(ctx context.Context, key []byte) ([]byte, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	s.atomicUpdate = false
	return s.get(ctx, s.Root, key, nil, 0, s.TrieHeight)
}

// get fetches the value of a key given a trie root
func (s *Trie) get(ctx context.Context, root, key []byte, batch [][]byte, iBatch, height int) ([]byte, error) {
	if len(root) == 0 {
		// the trie does not contain the key
		return nil, nil
	}
	// Fetch the children of the node
	batch, iBatch, lnode, rnode, isShortcut, err := s.loadChildren(ctx, root, height, iBatch, batch)
	if err != nil {
		return nil, err
	}
	if isShortcut {
		if bytes.Equal(lnode[:HashLength], key) {
			return rnode[:HashLength], nil
		}
		// also returns nil if height 0 is not a shortcut
		return nil, nil
	}
	if bitIsSet(key, s.TrieHeight-height) {
		return s.get(ctx, rnode, key, batch, 2*iBatch+2, height-1)
	}
	return s.get(ctx, lnode, key, batch, 2*iBatch+1, height-1)
}

func (s *Trie) Commit(ctx context.Context) error {
	err := s.db.commitChangesToDB(ctx)
	if err != nil {
		return err
	}
	return nil
}
