/**
 *  @file
 *  @copyright defined in aergo/LICENSE.txt
 */

package trie

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
)

var ErrorNoRow = errors.New("no row available")

// ReadRequest: Read request from client
// contains one channel to return the result
type ReadRequest struct {
	key        []byte
	resultChan chan<- ReadResult
}

// ReadResult: Read result to client
type ReadResult struct {
	result []byte
	err    error
}

// CacheDB: a cached db. It has one map in memory.
type CacheDB struct {
	// cachedNodes contains the first levels of the tree (nodes that have 2 non default children)
	liveCache map[Hash][][]byte

	// cacheMux is a lock for cachedNodes
	liveMux sync.RWMutex

	// updatedNodes that have will be flushed to disk
	updatedNodes map[Hash][][]byte

	// updatedMux is a lock for updatedNodes
	updatedMux sync.RWMutex

	// lock for CacheDB
	lock sync.RWMutex

	// dbConn is the conn to mysql db
	Store db.Conn

	removedNode map[Hash][]byte

	removeMux sync.RWMutex
}

// NewCacheDB: return a cached db
func NewCacheDB(store db.Conn) (*CacheDB, error) {
	// check if the table exists
	// if not, create a new one

	return &CacheDB{
		liveCache:    make(map[Hash][][]byte),
		updatedNodes: make(map[Hash][][]byte),
		removedNode:  make(map[Hash][]byte),
		Store:        store,
	}, nil
}

// commitChangesToDB stores the updated nodes to disk.
func (cacheDB *CacheDB) commitChangesToDB() error {
	cacheDB.updatedMux.Lock()
	defer cacheDB.updatedMux.Unlock()

	updates := []db.KeyValuePair{}
	for k, v := range cacheDB.updatedNodes {
		updates = append(updates, db.KeyValuePair{Key: k, Value: serializeBatch(v)})
	}
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	updateStart := time.Now()
	numOfWrites, err := cacheDB.Store.UpdateKeyValuesTreeStruc(ctx, updates)
	if err != nil {
		return fmt.Errorf("commitChangesToDB | UpdateKeyValuePairBatches | %w", err)
	}
	updateEnd := time.Now()
	fmt.Println("Update : takes ", updateEnd.Sub(updateStart), " | write ", numOfWrites)
	// clear update nodes
	cacheDB.updatedNodes = make(map[Hash][][]byte)

	if len(cacheDB.removedNode) > 0 {
		keys := []common.SHA256Output{}
		for k := range cacheDB.removedNode {
			keys = append(keys, k)
		}
		ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
		defer cancelF()

		start := time.Now()
		_, err = cacheDB.Store.DeleteKeyValuesTreeStruc(ctx, keys)
		if err != nil {
			return fmt.Errorf("commitChangesToDB | DeleteKeyValuePairBatches | %w", err)
		}
		end := time.Now()

		fmt.Println("Delete : takes ", end.Sub(start), " | delete ", len(cacheDB.removedNode))
		cacheDB.removedNode = make(map[Hash][]byte)

	}

	return nil
}

func (cacheDB *CacheDB) getValue(key []byte) ([]byte, error) {
	cacheDB.lock.Lock()

	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	key32Bytes := Hash{}
	copy(key32Bytes[:], key)

	result, err := cacheDB.Store.RetrieveOneKeyValuePairTreeStruc(ctx, key32Bytes)
	cacheDB.lock.Unlock()
	if err != nil {
		//cacheDB.lock.Unlock()
		return nil, fmt.Errorf("getValue | RetrieveOneKeyValuePair | %w", err)
	}
	if result.Value == nil {
		//cacheDB.lock.Unlock()
		return nil, ErrorNoRow
	}
	//cacheDB.lock.Unlock()
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

func (db *CacheDB) GetLiveCacheSize() int {
	return len(db.liveCache)
}

func (db *CacheDB) deleteUpdatedNodes(node common.SHA256Output) {
	db.updatedMux.Lock()
	delete(db.updatedNodes, node)
	db.updatedMux.Unlock()
}

func (db *CacheDB) deleteLiveCache(node common.SHA256Output) {
	db.liveMux.Lock()
	delete(db.liveCache, node)
	db.liveMux.Unlock()
}

func (db *CacheDB) getLiveCache(node common.SHA256Output) ([][]byte, bool) {
	db.liveMux.RLock()
	defer db.liveMux.RUnlock()
	val, exists := db.liveCache[node]
	return val, exists
}

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

func (db *CacheDB) updateLiveCache(node common.SHA256Output, value [][]byte) {
	db.liveMux.Lock()
	db.liveCache[node] = value
	db.liveMux.Unlock()
}

func (db *CacheDB) addRemoveNode(node common.SHA256Output) {
	db.removeMux.Lock()
	db.removedNode[node] = []byte{0}
	db.removeMux.Unlock()
}

/*
// Start: creates workers and starts the worker distributor thread,
func (db *CacheDB) Start() {
	workerChan := make(chan ReadRequest)
	for i := 0; i < 10; i++ {
		go workerThread(workerChan, db.Store, db.tableName)
	}
	workerDistributor(db.ClientInput, workerChan)
}



// queries the data, and return the result to the client
func workerThread(workerChan chan ReadRequest, db db.Conn, tableName string) {
	for {
		select {
		case newRequest := <-workerChan:
			readResult := ReadResult{}

			keyString := hex.EncodeToString(newRequest.key[:])
			queryGetStr := "SELECT value FROM `map`.`" + tableName + "` WHERE `key` = '" + keyString + "';"

			var valueString string
			err := db.QueryRow(queryGetStr).Scan(&valueString)
			if err != nil {
				readResult.err = fmt.Errorf("workerThread | QueryRow | %w", err)
				newRequest.resultChan <- readResult
				continue
			}

			value, err := hex.DecodeString(valueString)
			if err != nil {
				readResult.err = fmt.Errorf("workerThread | DecodeString | %w", err)
				newRequest.resultChan <- readResult
				continue
			}

			readResult.result = value
			newRequest.resultChan <- readResult
		}
	}
}
*/

/*
// Create or load a table (every table represnets one tree)
func initValueMap(db SQLDB, tableName string) (bool, error) {
	// query to check if table exists
	// defeult db schema = 'map'
	queryTableStr := "SELECT COUNT(*) FROM information_schema.tables  WHERE table_schema = 'map'  AND table_name = '" + tableName + "';"

	result, err := db.Query(queryTableStr)
	if err != nil {
		return false, fmt.Errorf("initValueMap | SELECT COUNT(*) | %w", err)
	}
	defer result.Close()

	// check if table exists
	var tableIsExisted bool
	result.Next()
	err = result.Scan(&tableIsExisted)
	if err != nil {
		return false, fmt.Errorf("initValueMap | Scan | %w", err)
	}

	// if table not exists -> this is a new tree (treeID does not exist)
	if !tableIsExisted {
		// create a new table with two columns
		// key             VARCHAR(64)             Primary Key
		// value           VARCHAR(4096)
		createMapStr := "CREATE TABLE `map`.`" + tableName + "` (`key` VARCHAR(64) NOT NULL, `value` VARCHAR(2048) NOT NULL, PRIMARY KEY (`key`));"
		newTable, err := db.Query(createMapStr)
		if err != nil {
			return false, fmt.Errorf("initValueMap | CREATE TABLE | %w", err)
		}
		defer newTable.Close()
	}
	return tableIsExisted, nil
}
*/
