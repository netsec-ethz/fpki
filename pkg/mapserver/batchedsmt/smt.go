package batchedsmt

// The Package Trie implements a sparse merkle trie.

import (
	"bytes"
	"database/sql"
	"fmt"
	"sync"
)

// updateResult is used to contain the updateResult of goroutines and is sent through a channel.
type updateResult struct {
	update []byte
	err    error
}

// SMT is a sparse Merkle tree.
type SMT struct {
	db *CacheDB
	// Root is the current root of the smt.
	Root []byte

	// lock is for the whole struct
	lock sync.RWMutex

	// hash is the hash function used in the trie
	hash func(data ...[]byte) []byte

	// defaultHashes are the default values of empty trees
	defaultHashes [][]byte

	// CacheHeightLimit is the number of tree levels we want to store in cache
	CacheHeightLimit int
}

// NewSMT creates a new SMT
func NewSMT(root []byte, hash func(data ...[]byte) []byte, store *sql.DB) (*SMT, error) {
	db, err := NewCacheDB(store)
	if err != nil {
		return nil, err
	}
	// start the worker thread
	go db.Start()
	smt := &SMT{
		hash:             hash,
		db:               db,
		CacheHeightLimit: TreeHeight + 1,
		Root:             root,
	}
	smt.loadDefaultHashes()
	return smt, err
}

// StoreUpdatedNode stores the updated nodes to disk
func (smt *SMT) StoreUpdatedNode() error {
	// TODO(yongzhe): lock might not be necessary?
	smt.lock.RLock()
	defer smt.lock.RUnlock()
	if smt.db.dbConn == nil {
		return fmt.Errorf("StoreUpdatedNode | DB not connected")
	}

	// write the cached data
	err := smt.db.writeCachedDataToDB()
	if err != nil {
		return fmt.Errorf("Commit | StoreUpdatedNode | %w", err)
	}

	// clear cache
	smt.db.updatedNodes = make(map[Hash][][]byte)
	return nil
}

// Update adds a sorted list of keys and their values to the tree
// NOTE: for values, use hash(key + content)
func (s *SMT) Update(keys, values [][]byte) ([]byte, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	// open a channel and wait for result from bot layer
	resultChan := make(chan updateResult, 1)
	s.update(s.Root, keys, values, nil, 0, TreeHeight, false, true, resultChan)
	result := <-resultChan

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

// GetLeafValue: return leaf value according to key
// TODO(yongzhe): maybe lock is not necessary?
func (smt *SMT) GetLeafValue(key []byte) ([]byte, error) {
	smt.lock.RLock()
	defer smt.lock.RUnlock()
	return smt.get(smt.Root, key, nil, 0, TreeHeight)
}

// loadChildren looks for the children of a node.
// if the node is not stored in cache, it will be loaded from db.
func (smt *SMT) loadChildren(root []byte, height, iBatch int, subTree [][]byte) ([][]byte, int, []byte, []byte, bool, error) {
	// whether this batch(sub-tree) only contains one node
	isShortcut := false

	// if this layer is the root of one sub-tree (four-layer-tree)
	if height%4 == 0 {
		// if this sub-tree is empty
		if len(root) == 0 {
			// create a new default batch(sub-tree)
			subTree = make([][]byte, 31, 31)
			subTree[0] = []byte{0}
		} else {
			var err error
			// get the sub-tree
			subTree, err = smt.loadSubTree(root[:HashLength])
			if err != nil {
				return nil, 0, nil, nil, false, fmt.Errorf("loadChildren | loadSubTree | %w", err)
			}
		}
		iBatch = 0
		// specific bit to identify the short cut
		if subTree[0][0] == 1 {
			isShortcut = true
		}
	} else {
		if len(subTree[iBatch]) != 0 && subTree[iBatch][HashLength] == 1 {
			isShortcut = true
		}
	}
	return subTree, iBatch, subTree[2*iBatch+1], subTree[2*iBatch+2], isShortcut, nil
}

// get fetches the value of a key given a tree root
func (smt *SMT) get(root []byte, key []byte, subTree [][]byte, posInBatch, height int) ([]byte, error) {
	// if the whole tree is empty
	if len(root) == 0 {
		return nil, nil
	}

	// if we reached the bot of the complete tree
	if height == 0 {
		return root[:HashLength], nil
	}

	// Fetch the children of the node
	subTree, posInBatch, lnode, rnode, isShortcut, err := smt.loadChildren(root, height, posInBatch, subTree)
	if err != nil {
		return nil, fmt.Errorf("get | loadChildren | %w", err)
	}

	// if this sub-tree only contains one leaf
	if isShortcut {
		if bytes.Equal(lnode[:HashLength], key) {
			return rnode[:HashLength], nil
		}
		// Never called?
		return nil, nil
	}
	if bitIsSet(key, TreeHeight-height) {
		return smt.get(rnode, key, subTree, 2*posInBatch+2, height-1)
	}
	return smt.get(lnode, key, subTree, 2*posInBatch+1, height-1)
}

// loadSubTree fetches a sub-tree in cache or db
func (smt *SMT) loadSubTree(root []byte) ([][]byte, error) {
	var node Hash
	copy(node[:], root)
	smt.db.cacheMux.RLock()
	val, exists := smt.db.cachedNodes[node]
	smt.db.cacheMux.RUnlock()

	// if sub-tree is in the cachedNodes
	if exists {
		return val, nil
	}

	// checking if the node is updated
	smt.db.updatedMux.RLock()
	val, exists = smt.db.updatedNodes[node]
	smt.db.updatedMux.RUnlock()
	if exists {
		return val, nil
	}

	//Fetch node in db
	if smt.db.dbConn == nil {
		return nil, fmt.Errorf("loadSubTree | DB not connected")
	}

	smt.db.lock.RLock()

	// send request to db, then receive result
	resultChan := make(chan ReadResult)
	smt.db.ClientInput <- ReadRequest{key: root, resultChan: resultChan}
	readResult := <-resultChan
	close(resultChan)

	smt.db.lock.RUnlock()

	if readResult.err != nil {
		return nil, fmt.Errorf("the trie node %x is unavailable in the disk db, db may be corrupted | %w", root, readResult.err)
	}

	//smt.db.lock.RUnlock()

	nodeSize := len(readResult.result)
	if nodeSize != 0 {
		return smt.parseBatch(readResult.result), nil
	}
	return nil, fmt.Errorf("the trie node %x is unavailable in the disk db, db may be corrupted", root)
}

// interiorHash hashes 2 children to get the parent hash and stores it in the updatedNodes and maybe in liveCache.
// the key is the hash and the value is the appended child nodes or the appended key/value in case of a shortcut.
// keys of go mappings cannot be byte slices so the hash is copied to a byte array
func (smt *SMT) interiorHash(left, right []byte, height, iBatch int, oldRoot []byte, shortcut, store bool, keys, values, batch [][]byte) []byte {
	var hashValue []byte
	if (len(left) == 0) && (len(right) == 0) {
		// if a key was deleted, the node becomes default
		batch[2*iBatch+1] = left
		batch[2*iBatch+2] = right
		smt.deleteOldNode(oldRoot, height)
		return nil
	} else if len(left) == 0 {
		hashValue = smt.hash(smt.defaultHashes[height-1], right[:HashLength])
	} else if len(right) == 0 {
		hashValue = smt.hash(left[:HashLength], smt.defaultHashes[height-1])
	} else {
		hashValue = smt.hash(left[:HashLength], right[:HashLength])
	}
	if !store {
		// a shortcut node cannot move up
		return append(hashValue, byte(0))
	}
	if !shortcut {
		hashValue = append(hashValue, byte(0))
	} else {
		// store the value at the shortcut node instead of height 0.
		hashValue = append(hashValue, byte(1))
		left = append(keys[0], byte(2))
		right = append(values[0], byte(2))
	}
	batch[2*iBatch+2] = right
	batch[2*iBatch+1] = left

	// maybe store batch node
	// if the node is a root of the sub-tree
	if (height)%4 == 0 {
		if shortcut {
			batch[0] = []byte{1}
		} else {
			batch[0] = []byte{0}
		}
		smt.storeNode(batch, hashValue, oldRoot, height)
	}
	return hashValue
}

// storeNode stores a batch and deletes the old node from cache
func (smt *SMT) storeNode(batch [][]byte, h, oldRoot []byte, height int) {
	if !bytes.Equal(h, oldRoot) {
		var node Hash
		copy(node[:], h)
		// record new node
		smt.db.updatedMux.Lock()
		smt.db.updatedNodes[node] = batch
		smt.db.updatedMux.Unlock()
		// Cache the shortcut node if it's height is over CacheHeightLimit
		if height >= smt.CacheHeightLimit {
			smt.db.cacheMux.Lock()
			smt.db.cachedNodes[node] = batch
			smt.db.cacheMux.Unlock()
		}
		// NOTE this could delete a node used by another part of the tree
		// if some values are equal and update is called multiple times without commit.
		smt.deleteOldNode(oldRoot, height)
	}
}

// deleteOldNode deletes an old node that has been updated
func (smt *SMT) deleteOldNode(root []byte, height int) {
	var node Hash
	copy(node[:], root)

	smt.db.updatedMux.Lock()
	delete(smt.db.updatedNodes, node)
	smt.db.updatedMux.Unlock()

	if height >= smt.CacheHeightLimit {
		smt.db.cacheMux.Lock()
		delete(smt.db.cachedNodes, node)
		smt.db.cacheMux.Unlock()
	}
}

// loadDefaultHashes creates the default hashes
func (s *SMT) loadDefaultHashes() {
	s.defaultHashes = make([][]byte, TreeHeight+1)
	s.defaultHashes[0] = DefaultLeaf
	var h []byte
	for i := 1; i <= int(TreeHeight); i++ {
		h = s.hash(s.defaultHashes[i-1], s.defaultHashes[i-1])
		s.defaultHashes[i] = h
	}
}
