/**
 *  @file
 *  @copyright defined in aergo/LICENSE.txt
 */

package trie

import (
	"bytes"
	"context"
	"fmt"
	"sync"
)

// Trie is a modified sparse Merkle tree.
// Instead of storing values at the leaves of the tree,
// the values are stored at the highest subtree root that contains only that value.
// If the tree is sparse, this requires fewer hashing operations.
type Trie struct {
	db *CacheDB
	// Root is the current root of the smt.
	Root []byte
	// prevRoot is the root before the last update
	prevRoot []byte
	// lock is for the whole struct
	lock sync.RWMutex
	// hash is the hash function used in the trie
	hash func(data ...[]byte) []byte
	// TrieHeight is the number if bits in a key
	TrieHeight int
	// LoadDbCounter counts the nb of db reads in on update
	LoadDbCounter int
	// loadDbMux is a lock for LoadDbCounter
	loadDbMux sync.RWMutex
	// LoadCacheCounter counts the nb of cache reads in on update
	LoadCacheCounter int
	// liveCountMux is a lock fo LoadCacheCounter
	liveCountMux sync.RWMutex
	// counterOn is used to enable/disable for efficiency
	counterOn bool
	// CacheHeightLimit is the number of tree levels we want to store in cache
	CacheHeightLimit int
	// pastTries stores the past maxPastTries trie roots to revert
	pastTries [][]byte
	// atomicUpdate, commit all the changes made by intermediate update calls
	atomicUpdate bool
}

// NewSMT creates a new SMT given a keySize and a hash function.
func NewTrie(root []byte, hash func(data ...[]byte) []byte, store DBConn) (*Trie, error) {
	s := &Trie{
		hash:       hash,
		TrieHeight: len(hash([]byte("height"))) * 8, // hash any string to get output length
		counterOn:  false,
	}
	var err error
	s.db, err = NewCacheDB(store)
	if err != nil {
		return nil, err
	}

	// don't store any cache by default (contracts state don't use cache)
	s.CacheHeightLimit = s.TrieHeight + 1
	s.Root = root
	return s, nil
}

func (s *Trie) PrintCacheSize() {
	fmt.Println(s.db.GetLiveCacheSize())
}

func (s *Trie) Close() error {
	return s.db.Store.Close()
}

// Update adds and deletes a sorted list of keys and their values to the trie.
// Adding and deleting can be simultaneous.
// To delete, set the value to DefaultLeaf.
// If Update is called multiple times, only the state after the last update is committed.
func (s *Trie) Update(ctx context.Context, keys, values [][]byte) ([]byte, error) {
	if len(keys) != len(values) {
		return nil, fmt.Errorf("key value size does not match")
	}
	if len(keys) == 0 {
		return nil, nil
	}

	s.lock.Lock()
	defer s.lock.Unlock()
	s.atomicUpdate = false
	s.LoadDbCounter = 0
	s.LoadCacheCounter = 0
	ch := make(chan mResult, 1)
	s.update(ctx, s.Root, keys, values, nil, 0, s.TrieHeight, ch)
	result := <-ch
	if result.err != nil {
		return nil, result.err
	}
	if len(result.update) != 0 {
		s.Root = result.update[:HashLength]
	} else {
		s.Root = nil
	}
	return s.Root, nil
}

// AtomicUpdate can be called multiple times and all the updated nodes will be committed
// and roots will be stored in past tries.
// Can be used for updating several blocks before committing to DB.
func (s *Trie) AtomicUpdate(ctx context.Context, keys, values [][]byte) ([]byte, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.atomicUpdate = true
	s.LoadDbCounter = 0
	s.LoadCacheCounter = 0
	ch := make(chan mResult, 1)
	s.update(ctx, s.Root, keys, values, nil, 0, s.TrieHeight, ch)
	result := <-ch
	if result.err != nil {
		return nil, result.err
	}
	if len(result.update) != 0 {
		s.Root = result.update[:HashLength]
	} else {
		s.Root = nil
	}
	s.updatePastTries()
	return s.Root, nil
}

// mResult is used to contain the result of goroutines and is sent through a channel.
type mResult struct {
	update []byte
	// flag if a node was deleted and a shortcut node maybe has to move up the tree
	deleted bool
	err     error
}

// update adds and deletes a sorted list of keys and their values to the trie.
// Adding and deleting can be simultaneous.
// To delete, set the value to DefaultLeaf.
// It returns the root of the updated tree.
func (s *Trie) update(ctx context.Context, root []byte, keys, values, batch [][]byte, iBatch,
	height int, ch chan<- (mResult)) {

	if len(keys) == 0 {
		ch <- mResult{}
		return
	}

	if height == 0 {
		if bytes.Equal(DefaultLeaf, values[0]) {
			// Delete the key-value from the trie if it is being set to DefaultLeaf
			// The value will be set to [] in batch by maybeMoveUpShortcut or interiorHash
			s.deleteOldNode(root, height, false)
			ch <- mResult{nil, true, nil}
		} else {
			// create a new shortcut batch.
			// simply storing the value will make it hard to move up the
			// shortcut in case of sibling deletion
			batch = make([][]byte, 31, 31)
			node := s.leafHash(keys[0], values[0], root, batch, 0, height)
			ch <- mResult{node, false, nil}
		}
		return
	}

	var rootCopy [32]byte
	copy(rootCopy[:], root)

	// Load the node to update
	batch, iBatch, lNode, rNode, isShortcut, err := s.loadChildren(ctx, root, height, iBatch, batch)
	if err != nil {
		ch <- mResult{nil, false, err}
		return
	}
	// Check if the keys are updating the shortcut node
	if isShortcut {
		keys, values = s.maybeAddShortcutToKV(keys, values, lNode[:HashLength], rNode[:HashLength])
		if iBatch == 0 {
			// shortcut is moving so it's root will change
			s.deleteOldNode(root, height, false)
		}
		// The shortcut node was added to keys and values so consider this subtree default.
		lNode, rNode = nil, nil
		// update in the batch (set key, value to default so the next loadChildren is correct)
		batch[2*iBatch+1] = nil
		batch[2*iBatch+2] = nil
		if len(keys) == 0 {
			// Set true so that a potential sibling shortcut may move up.
			ch <- mResult{nil, true, nil}
			return
		}
	}
	// Store shortcut node
	if (len(lNode) == 0) && (len(rNode) == 0) && (len(keys) == 1) {
		// We are adding 1 key to an empty subtree so store it as a shortcut
		if bytes.Equal(DefaultLeaf, values[0]) {
			ch <- mResult{nil, true, nil}
		} else {
			if rootCopy != [32]byte{0} && height%4 == 0 {
				s.db.addRemoveNode(rootCopy)
			}
			node := s.leafHash(keys[0], values[0], root, batch, iBatch, height)
			ch <- mResult{node, false, nil}
		}
		return
	}

	// Split the keys array so each branch can be updated in parallel
	lKeys, rKeys := s.splitKeys(keys, s.TrieHeight-height)
	splitIndex := len(lKeys)
	lValues, rValues := values[:splitIndex], values[splitIndex:]

	switch {
	case len(lKeys) == 0 && len(rKeys) > 0:
		if rootCopy != [32]byte{0} && height%4 == 0 {
			s.db.addRemoveNode(rootCopy)
		}

		s.updateRight(ctx, lNode, rNode, root, keys, values, batch, iBatch, height, ch)
	case len(lKeys) > 0 && len(rKeys) == 0:
		if rootCopy != [32]byte{0} && height%4 == 0 {
			s.db.addRemoveNode(rootCopy)
		}

		s.updateLeft(ctx, lNode, rNode, root, keys, values, batch, iBatch, height, ch)
	default:
		if rootCopy != [32]byte{0} && height%4 == 0 {
			s.db.addRemoveNode(rootCopy)
		}

		s.updateParallel(ctx, lNode, rNode, root, lKeys, rKeys, lValues, rValues, batch, iBatch, height, ch)
	}
}

// updateRight updates the right side of the tree
func (s *Trie) updateRight(ctx context.Context, lNode, rNode, root []byte, keys, values, batch [][]byte, iBatch, height int, ch chan<- (mResult)) {
	// all the keys go in the right subtree
	newCh := make(chan mResult, 1)
	s.update(ctx, rNode, keys, values, batch, 2*iBatch+2, height-1, newCh)
	result := <-newCh
	if result.err != nil {
		ch <- mResult{nil, false, result.err}
		return
	}
	// Move up a shortcut node if necessary.
	if result.deleted {
		if s.maybeMoveUpShortcut(ctx, lNode, result.update, root, batch, iBatch, height, ch) {
			return
		}
	}
	node := s.interiorHash(lNode, result.update, root, batch, iBatch, height)
	ch <- mResult{node, false, nil}
}

// updateLeft updates the left side of the tree
func (s *Trie) updateLeft(ctx context.Context, lNode, rNode, root []byte, keys, values, batch [][]byte, iBatch, height int, ch chan<- (mResult)) {
	// all the keys go in the left subtree
	newCh := make(chan mResult, 1)
	s.update(ctx, lNode, keys, values, batch, 2*iBatch+1, height-1, newCh)
	result := <-newCh
	if result.err != nil {
		ch <- mResult{nil, false, result.err}
		return
	}
	// Move up a shortcut node if necessary.
	if result.deleted {
		if s.maybeMoveUpShortcut(ctx, result.update, rNode, root, batch, iBatch, height, ch) {
			return
		}
	}
	node := s.interiorHash(result.update, rNode, root, batch, iBatch, height)
	ch <- mResult{node, false, nil}
}

// updateParallel updates both sides of the trie simultaneously
func (s *Trie) updateParallel(ctx context.Context, lNode, rNode, root []byte, lKeys, rKeys, lValues, rValues, batch [][]byte, iBatch, height int, ch chan<- (mResult)) {
	lch := make(chan mResult, 1)
	rch := make(chan mResult, 1)
	go s.update(ctx, lNode, lKeys, lValues, batch, 2*iBatch+1, height-1, lch)
	go s.update(ctx, rNode, rKeys, rValues, batch, 2*iBatch+2, height-1, rch)
	lResult := <-lch
	rResult := <-rch
	if lResult.err != nil {
		ch <- mResult{nil, false, lResult.err}
		return
	}
	if rResult.err != nil {
		ch <- mResult{nil, false, rResult.err}
		return
	}

	// Move up a shortcut node if it's sibling is default
	if lResult.deleted || rResult.deleted {
		if s.maybeMoveUpShortcut(ctx, lResult.update, rResult.update, root, batch, iBatch, height, ch) {
			return
		}
	}
	node := s.interiorHash(lResult.update, rResult.update, root, batch, iBatch, height)
	ch <- mResult{node, false, nil}
}

// deleteOldNode deletes an old node that has been updated
func (s *Trie) deleteOldNode(root []byte, height int, movingUp bool) {
	var node Hash
	copy(node[:], root)
	if !s.atomicUpdate || movingUp {
		// don't delete old nodes with atomic updated except when
		// moving up a shortcut, we don't record every single move
		s.db.deleteUpdatedNodes(node)

	}
	if height >= s.CacheHeightLimit {
		s.db.deleteLiveCache(node)
	}
}

// splitKeys divides the array of keys into 2 so they can update left and right branches in parallel
func (s *Trie) splitKeys(keys [][]byte, height int) ([][]byte, [][]byte) {
	for i, key := range keys {
		if bitIsSet(key, height) {
			return keys[:i], keys[i:]
		}
	}
	return keys, nil
}

// maybeMoveUpShortcut moves up a shortcut if it's sibling node is default
func (s *Trie) maybeMoveUpShortcut(ctx context.Context, left, right, root []byte, batch [][]byte, iBatch, height int, ch chan<- (mResult)) bool {
	if len(left) == 0 && len(right) == 0 {
		// Both update and sibling are deleted subtrees
		if iBatch == 0 {
			// If the deleted subtrees are at the root, then delete it.
			s.deleteOldNode(root, height, true)
		} else {
			batch[2*iBatch+1] = nil
			batch[2*iBatch+2] = nil
		}
		ch <- mResult{nil, true, nil}
		return true
	} else if len(left) == 0 {
		// If right is a shortcut move it up
		if right[HashLength] == 1 {
			s.moveUpShortcut(ctx, right, root, batch, iBatch, 2*iBatch+2, height, ch)
			return true
		}
	} else if len(right) == 0 {
		// If left is a shortcut move it up
		if left[HashLength] == 1 {
			s.moveUpShortcut(ctx, left, root, batch, iBatch, 2*iBatch+1, height, ch)
			return true
		}
	}
	return false
}

func (s *Trie) moveUpShortcut(ctx context.Context, shortcut, root []byte, batch [][]byte, iBatch, iShortcut, height int, ch chan<- (mResult)) {
	// it doesn't matter if atomic update is true or false since the batch is node modified
	_, _, shortcutKey, shortcutVal, _, err := s.loadChildren(ctx, shortcut, height-1, iShortcut, batch)
	if err != nil {
		ch <- mResult{nil, false, err}
		return
	}
	// when moving up the shortcut, it's hash will change because height is +1
	newShortcut := s.hash(shortcutKey[:HashLength], shortcutVal[:HashLength], []byte{byte(height)})
	newShortcut = append(newShortcut, byte(1))

	if iBatch == 0 {
		// Modify batch to a shortcut batch
		batch[0] = []byte{1}
		batch[2*iBatch+1] = shortcutKey
		batch[2*iBatch+2] = shortcutVal
		batch[2*iShortcut+1] = nil
		batch[2*iShortcut+2] = nil
		// cache and updatedNodes deleted by store node
		s.storeNode(batch, newShortcut, root, height)
	} else if (height-1)%4 == 0 {
		// move up shortcut and delete old batch
		batch[2*iBatch+1] = shortcutKey
		batch[2*iBatch+2] = shortcutVal
		// set true so that AtomicUpdate can also delete a node moving up
		// otherwise every nodes moved up is recorded
		s.deleteOldNode(shortcut, height, true)
	} else {
		//move up shortcut
		batch[2*iBatch+1] = shortcutKey
		batch[2*iBatch+2] = shortcutVal
		batch[2*iShortcut+1] = nil
		batch[2*iShortcut+2] = nil
	}
	// Return the left sibling node to move it up
	ch <- mResult{newShortcut, true, nil}
}

// maybeAddShortcutToKV adds a shortcut key to the keys array to be updated.
// this is used when a subtree containing a shortcut node is being updated
func (s *Trie) maybeAddShortcutToKV(keys, values [][]byte, shortcutKey, shortcutVal []byte) ([][]byte, [][]byte) {
	newKeys := make([][]byte, 0, len(keys)+1)
	newValues := make([][]byte, 0, len(keys)+1)

	if bytes.Compare(shortcutKey, keys[0]) < 0 {
		newKeys = append(newKeys, shortcutKey)
		newKeys = append(newKeys, keys...)
		newValues = append(newValues, shortcutVal)
		newValues = append(newValues, values...)
	} else if bytes.Compare(shortcutKey, keys[len(keys)-1]) > 0 {
		newKeys = append(newKeys, keys...)
		newKeys = append(newKeys, shortcutKey)
		newValues = append(newValues, values...)
		newValues = append(newValues, shortcutVal)
	} else {
		higher := false
		for i, key := range keys {
			if bytes.Equal(shortcutKey, key) {
				if !bytes.Equal(DefaultLeaf, values[i]) {
					// Do nothing if the shortcut is simply updated
					return keys, values
				}
				// Delete shortcut if it is updated to DefaultLeaf
				newKeys = append(newKeys, keys[:i]...)
				newKeys = append(newKeys, keys[i+1:]...)
				newValues = append(newValues, values[:i]...)
				newValues = append(newValues, values[i+1:]...)
			}
			if !higher && bytes.Compare(shortcutKey, key) > 0 {
				higher = true
				continue
			}
			if higher && bytes.Compare(shortcutKey, key) < 0 {
				// insert shortcut in slices
				newKeys = append(newKeys, keys[:i]...)
				newKeys = append(newKeys, shortcutKey)
				newKeys = append(newKeys, keys[i:]...)
				newValues = append(newValues, values[:i]...)
				newValues = append(newValues, shortcutVal)
				newValues = append(newValues, values[i:]...)
				break
			}
		}
	}
	return newKeys, newValues
}

// loadChildren looks for the children of a node.
// if the node is not stored in cache, it will be loaded from db.
func (s *Trie) loadChildren(ctx context.Context, root []byte, height, iBatch int, batch [][]byte) ([][]byte, int, []byte, []byte, bool, error) {
	isShortcut := false
	if height%4 == 0 {
		if len(root) == 0 {
			// create a new default batch
			batch = make([][]byte, 31)
			batch[0] = []byte{0}
		} else {
			var err error
			batch, err = s.loadBatch(ctx, root, height)
			if err != nil {
				return nil, 0, nil, nil, false, err
			}
		}
		iBatch = 0
		if batch[0][0] == 1 {
			isShortcut = true
		}
	} else {
		if len(batch[iBatch]) != 0 && batch[iBatch][HashLength] == 1 {
			isShortcut = true
		}
	}
	return batch, iBatch, batch[2*iBatch+1], batch[2*iBatch+2], isShortcut, nil
}

// loadBatch fetches a batch of nodes in cache or db
func (s *Trie) loadBatch(ctx context.Context, root []byte, height int) ([][]byte, error) {
	var node Hash
	copy(node[:], root)

	val, exists := s.db.getLiveCache(node)

	if exists {
		if s.atomicUpdate {
			// Return a copy so that Commit() doesn't have to be called at
			// each block and still commit every state transition.
			// Before Commit, the same batch is in liveCache and in updatedNodes
			newVal := make([][]byte, 31)
			copy(newVal, val)
			return newVal, nil
		}
		return val, nil
	}
	// checking updated nodes is useful if get() or update() is called twice in a row without db commit
	val, exists = s.db.getUpdatedNodes(node)
	if exists {
		if s.atomicUpdate {
			// Return a copy so that Commit() doesn't have to be called at
			// each block and still commit every state transition.
			newVal := make([][]byte, 31)
			copy(newVal, val)
			return newVal, nil
		}
		return val, nil
	}
	//Fetch node in disk database
	value, err := s.db.getValueLockFree(ctx, root[:HashLength])
	if err != nil {
		return nil, fmt.Errorf("the trie node %x is unavailable in the disk db, db may be corrupted | %w", root, err)
	}

	var rootCopy [32]byte
	copy(rootCopy[:], root[:HashLength])

	nodeSize := len(value)
	if nodeSize != 0 {
		// Added: add the newly fetched nodes, and cache them into memory
		resultBytes := parseBatch(value)
		if height >= s.CacheHeightLimit && height%4 == 0 {
			s.db.updateLiveCache(rootCopy, resultBytes)
		}
		return resultBytes, nil
	}
	return nil, fmt.Errorf("the trie node %x is unavailable in the disk db, db may be corrupted", root)
}

// leafHash returns the hash of key_value_byte(height) concatenated, stores it in the updatedNodes and maybe in liveCache.
// leafHash is never called for a default value. Default value should not be stored.
func (s *Trie) leafHash(key, value, oldRoot []byte, batch [][]byte, iBatch, height int) []byte {
	// byte(height) is here for 2 reasons.
	// 1- to prevent potential problems with merkle proofs where if an account
	// has the same address as a node, it would be possible to prove a
	// different value for the account.
	// 2- when accounts are added to the trie, accounts on their path get pushed down the tree
	// with them. if an old account changes position from a shortcut batch to another
	// shortcut batch of different height, if would be deleted when reverting.
	h := s.hash(key, value, []byte{byte(height)})
	h = append(h, byte(1)) // byte(1) is a flag for the shortcut
	batch[2*iBatch+2] = append(value, byte(2))
	batch[2*iBatch+1] = append(key, byte(2))
	if height%4 == 0 {
		batch[0] = []byte{1} // byte(1) is a flag for the shortcut batch
		s.storeNode(batch, h, oldRoot, height)
	}
	return h
}

// storeNode stores a batch and deletes the old node from cache
func (s *Trie) storeNode(batch [][]byte, h, oldRoot []byte, height int) {
	if !bytes.Equal(h, oldRoot) {
		var node Hash
		copy(node[:], h)
		// record new node
		s.db.updateUpdateNodes(node, batch)
		// Cache the shortcut node if it's height is over CacheHeightLimit
		if height >= s.CacheHeightLimit {
			s.db.updateLiveCache(node, batch)
		}
		s.deleteOldNode(oldRoot, height, false)
	}
}

// interiorHash hashes 2 children to get the parent hash and stores it in the updatedNodes and maybe in liveCache.
func (s *Trie) interiorHash(left, right, oldRoot []byte, batch [][]byte, iBatch, height int) []byte {
	var h []byte
	// left and right cannot both be default. It is handled by maybeMoveUpShortcut()
	if len(left) == 0 {
		h = s.hash(DefaultLeaf, right[:HashLength])
	} else if len(right) == 0 {
		h = s.hash(left[:HashLength], DefaultLeaf)
	} else {
		h = s.hash(left[:HashLength], right[:HashLength])
	}
	h = append(h, byte(0))
	batch[2*iBatch+2] = right
	batch[2*iBatch+1] = left
	if height%4 == 0 {
		batch[0] = []byte{0}
		s.storeNode(batch, h, oldRoot, height)
	}
	return h
}

// updatePastTries appends the current Root to the list of past tries
func (s *Trie) updatePastTries() {
	if len(s.pastTries) >= maxPastTries {
		copy(s.pastTries, s.pastTries[1:])
		s.pastTries[len(s.pastTries)-1] = s.Root
	} else {
		s.pastTries = append(s.pastTries, s.Root)
	}
}

func (s *Trie) GetLiveCacheSize() int {
	return s.db.GetLiveCacheSize()
}

func (s *Trie) ResetLiveCache() {
	s.db.liveCache = make(map[Hash][][]byte)
}

// parseBatch decodes the byte data into a slice of nodes and bitmap
func parseBatch(val []byte) [][]byte {
	batch := make([][]byte, 31)
	// check if the batch root is a shortcut
	if bitIsSet(val, 31) {
		batch[0] = []byte{1}
		batch[1] = val[4 : 4+33]
		batch[2] = val[4+33 : 4+33*2]
	} else {
		batch[0] = []byte{0}
		j := 0
		for i := 1; i <= 30; i++ {
			if bitIsSet(val[:4], i-1) {
				batch[i] = val[4+33*j : 4+33*(j+1)]
				j++
			}
		}
	}
	return batch
}
