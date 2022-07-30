/**
 *  @file
 *  @copyright defined in aergo/LICENSE.txt
 */

package trie

import (
	"context"
	"fmt"
	"sync"

	_ "github.com/go-sql-driver/mysql"
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
)

// CacheDB: a cached db. It has one map in memory.
type CacheDB struct {
	// cachedNodes contains the first levels of the tree (nodes that have 2 non default children)
	liveCache map[Hash][][]byte
	liveMux   sync.RWMutex

	// updatedNodes that have will be flushed to disk
	updatedNodes map[Hash][][]byte
	updatedMux   sync.RWMutex

	// wholeCacheDBLock for CacheDB
	wholeCacheDBLock sync.RWMutex

	// dbConn is the conn to mysql db
	Store       db.Conn
	readLimiter chan struct{}

	// nodes to be removed from db
	removedNode map[Hash][]byte
	removeMux   sync.RWMutex
}

// NewCacheDB: return a cached db
func NewCacheDB(store db.Conn) (*CacheDB, error) {
	return &CacheDB{
		liveCache:    make(map[Hash][][]byte),
		updatedNodes: make(map[Hash][][]byte),
		removedNode:  make(map[Hash][]byte),
		Store:        store,
		readLimiter:  make(chan struct{}, 1),
	}, nil
}

// commitChangesToDB stores the updated nodes to disk.
func (cacheDB *CacheDB) commitChangesToDB(ctx context.Context) error {
	// prepare value to store
	updatesToDB := []*db.KeyValuePair{}
	keysToDelete := []common.SHA256Output{}

	// get nodes from update map
	cacheDB.updatedMux.Lock()
	for k, v := range cacheDB.updatedNodes {
		updatesToDB = append(updatesToDB, &db.KeyValuePair{Key: k, Value: serializeBatch(v)})
	}
	cacheDB.updatedNodes = make(map[Hash][][]byte)
	cacheDB.updatedMux.Unlock()

	// get nodes from remove map
	cacheDB.removeMux.Lock()

	for k := range cacheDB.removedNode {
		keysToDelete = append(keysToDelete, k)
	}

	cacheDB.removedNode = make(map[Hash][]byte)
	cacheDB.removeMux.Unlock()

	// lock the db; other thread should not read or write to db during the updates
	cacheDB.wholeCacheDBLock.Lock()
	defer cacheDB.wholeCacheDBLock.Unlock()

	_, err := cacheDB.Store.UpdateTreeNodes(ctx, updatesToDB)
	if err != nil {
		return fmt.Errorf("commitChangesToDB | UpdateKeyValuePairBatches | %w", err)
	}

	if len(keysToDelete) > 0 {
		_, err := cacheDB.Store.DeleteTreeNodes(ctx, keysToDelete)
		if err != nil {
			return fmt.Errorf("commitChangesToDB | DeleteKeyValuePairBatches | %w", err)
		}
	}

	return nil
}

func (cacheDB *CacheDB) getValueLimit(ctx context.Context, key []byte) ([]byte, error) {
	cacheDB.readLimiter <- struct{}{}        // block until there is some slack
	defer func() { <-cacheDB.readLimiter }() // ensure we'll give some slack
	return cacheDB.getValueLockFree(ctx, key)
}

func (cacheDB *CacheDB) getValueLockFree(ctx context.Context, key []byte) ([]byte, error) {
	value, err := cacheDB.Store.RetrieveTreeNode(ctx, *(*[32]byte)(key))
	if err != nil {
		return nil, fmt.Errorf("getValue | RetrieveOneKeyValuePair | %w", err)
	}
	return value, nil
}

// serializeBatch serializes the 2D [][]byte into a []byte for db
func serializeBatch(batch [][]byte) []byte {
	serialized := make([]byte, 4) //, 30*33)
	if batch[0][0] == 1 {
		// the batch node is a shortcut
		bitSet(serialized, 31)
	}
	for i := 1; i < 31; i++ {
		if len(batch[i]) != 0 {
			bitSet(serialized, i-1)
			serialized = append(serialized, batch[i]...)
		}
	}
	return serialized
}

//**************************************************
//          functions for live cache
//**************************************************
// GetLiveCacheSize: get current size of live cache
func (db *CacheDB) GetLiveCacheSize() int {
	return len(db.liveCache)
}

// deleteLiveCache: delete current nodes in live cache
func (db *CacheDB) deleteLiveCache(node common.SHA256Output) {
	db.liveMux.Lock()
	delete(db.liveCache, node)
	db.liveMux.Unlock()
}

// updateLiveCache: update the key-value store in the live cache
func (db *CacheDB) updateLiveCache(node common.SHA256Output, value [][]byte) {
	db.liveMux.Lock()
	db.liveCache[node] = value
	db.liveMux.Unlock()
}

// getLiveCache: get one node from live cache
func (db *CacheDB) getLiveCache(node common.SHA256Output) ([][]byte, bool) {
	db.liveMux.RLock()
	defer db.liveMux.RUnlock()
	val, exists := db.liveCache[node]
	return val, exists
}

//**************************************************
//          functions for updated nodes
//**************************************************
// getUpdatedNodes: get one node from updated nodes
func (db *CacheDB) getUpdatedNodes(node common.SHA256Output) ([][]byte, bool) {
	db.updatedMux.RLock()
	defer db.updatedMux.RUnlock()
	val, exists := db.updatedNodes[node]
	return val, exists
}

// updateUpdateNodes: update one node in updated nodes
func (db *CacheDB) updateUpdateNodes(node common.SHA256Output, value [][]byte) {
	db.updatedMux.Lock()
	db.updatedNodes[node] = value
	db.updatedMux.Unlock()
}

// deleteUpdatedNodes: remove updated nodes
func (db *CacheDB) deleteUpdatedNodes(node common.SHA256Output) {
	db.updatedMux.Lock()
	delete(db.updatedNodes, node)
	db.updatedMux.Unlock()
}

//**************************************************
//          functions for removed nodes
//**************************************************

// addRemoveNode: add node to remove
func (db *CacheDB) addRemoveNode(node common.SHA256Output) {
	db.removeMux.Lock()
	db.removedNode[node] = []byte{0}
	db.removeMux.Unlock()
}
