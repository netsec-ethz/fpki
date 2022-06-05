/**
 *  @file
 *  @copyright defined in aergo/LICENSE.txt
 */

package trie

import (
	"context"
	"fmt"
	"sync"
	"time"

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

	// lock for CacheDB
	lock sync.RWMutex

	// dbConn is the conn to mysql db
	Store db.Conn

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
	}, nil
}

// commitChangesToDB stores the updated nodes to disk.
func (cacheDB *CacheDB) commitChangesToDB(ctx context.Context) error {
	// prepare value to store
	updates := []db.KeyValuePair{}
	keys := []common.SHA256Output{}

	// get nodes from update map
	cacheDB.updatedMux.Lock()
	for k, v := range cacheDB.updatedNodes {
		updates = append(updates, db.KeyValuePair{Key: k, Value: serializeBatch(v)})
	}
	cacheDB.updatedNodes = make(map[Hash][][]byte)
	cacheDB.updatedMux.Unlock()

	// get nodes from remove map
	cacheDB.removeMux.Lock()
	if len(cacheDB.removedNode) > 0 {
		for k := range cacheDB.removedNode {
			keys = append(keys, k)
		}
	}
	cacheDB.removedNode = make(map[Hash][]byte)
	cacheDB.removeMux.Unlock()

	// lock the db; other thread should not read or write to db during the updates
	cacheDB.lock.Lock()
	defer cacheDB.lock.Unlock()

	updateStart := time.Now()
	_, err := cacheDB.Store.UpdateKeyValuesTreeStruc(ctx, updates)
	if err != nil {
		return fmt.Errorf("commitChangesToDB | UpdateKeyValuePairBatches | %w", err)
	}
	updateEnd := time.Now()
	fmt.Println("SMT DB Update : takes ", updateEnd.Sub(updateStart), " | write ", len(updates))

	if len(keys) > 0 {
		start := time.Now()
		_, err := cacheDB.Store.DeleteKeyValuesTreeStruc(ctx, keys)
		if err != nil {
			return fmt.Errorf("commitChangesToDB | DeleteKeyValuePairBatches | %w", err)
		}
		end := time.Now()
		fmt.Println("SMT DB Delete : takes ", end.Sub(start), " | delete ", len(keys))
	}

	return nil
}

// get a key-value pair from db
func (cacheDB *CacheDB) getValue(ctx context.Context, key []byte) ([]byte, error) {
	cacheDB.lock.Lock()

	key32Bytes := Hash{}
	copy(key32Bytes[:], key)

	result, err := cacheDB.Store.RetrieveOneKeyValuePairTreeStruc(ctx, key32Bytes)
	cacheDB.lock.Unlock()
	if err != nil {
		return nil, fmt.Errorf("getValue | RetrieveOneKeyValuePair | %w", err)
	}

	return result.Value, nil
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
func (db *CacheDB) GetLiveCacheSize() int {
	return len(db.liveCache)
}

func (db *CacheDB) deleteLiveCache(node common.SHA256Output) {
	db.liveMux.Lock()
	delete(db.liveCache, node)
	db.liveMux.Unlock()
}

func (db *CacheDB) updateLiveCache(node common.SHA256Output, value [][]byte) {
	db.liveMux.Lock()
	db.liveCache[node] = value
	db.liveMux.Unlock()
}

func (db *CacheDB) getLiveCache(node common.SHA256Output) ([][]byte, bool) {
	db.liveMux.RLock()
	defer db.liveMux.RUnlock()
	val, exists := db.liveCache[node]
	return val, exists
}

//**************************************************
//          functions for updated nodes
//**************************************************

func (db *CacheDB) getUpdatedNodes(node common.SHA256Output) ([][]byte, bool) {
	db.updatedMux.RLock()
	defer db.updatedMux.RUnlock()
	val, exists := db.updatedNodes[node]
	return val, exists
}

func (db *CacheDB) updateUpdateNodes(node common.SHA256Output, value [][]byte) {
	db.updatedMux.Lock()
	db.updatedNodes[node] = value
	db.updatedMux.Unlock()
}

//**************************************************
//          functions for removed nodes
//**************************************************

func (db *CacheDB) addRemoveNode(node common.SHA256Output) {
	db.removeMux.Lock()
	db.removedNode[node] = []byte{0}
	db.removeMux.Unlock()
}

func (db *CacheDB) deleteUpdatedNodes(node common.SHA256Output) {
	db.updatedMux.Lock()
	delete(db.updatedNodes, node)
	db.updatedMux.Unlock()
}
