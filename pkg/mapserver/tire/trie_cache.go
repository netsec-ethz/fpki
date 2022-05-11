/**
 *  @file
 *  @copyright defined in aergo/LICENSE.txt
 */

package trie

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

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
	Store *sql.DB

	removedNode map[Hash][]byte

	removeMux sync.RWMutex

	// Client is the channel for user input; Used to get read request from client
	ClientInput chan ReadRequest

	tableName string
}

// NewCacheDB: return a cached db
func NewCacheDB(store *sql.DB, tableName string) (*CacheDB, error) {
	// check if the table exists
	// if not, create a new one
	_, err := initValueMap(store, tableName)
	if err != nil {
		return nil, fmt.Errorf("NewCacheDB | initValueMap | %w", err)
	}

	// channel for the client input
	clientInput := make(chan ReadRequest)

	return &CacheDB{
		liveCache:    make(map[Hash][][]byte),
		updatedNodes: make(map[Hash][][]byte),
		removedNode:  make(map[Hash][]byte),
		Store:        store,
		ClientInput:  clientInput,
		tableName:    tableName,
	}, nil
}

// Start: creates workers and starts the worker distributor thread,
func (db *CacheDB) Start() {
	workerChan := make(chan ReadRequest)
	for i := 0; i < 10; i++ {
		go workerThread(workerChan, db.Store, db.tableName)
	}
	workerDistributor(db.ClientInput, workerChan)
}

// worker distributor func
func workerDistributor(clientInpuht chan ReadRequest, workerChan chan ReadRequest) {
	for {
		select {
		case newRequest := <-clientInpuht:
			{
				workerChan <- newRequest
			}
		}
	}
}

// queries the data, and return the result to the client
func workerThread(workerChan chan ReadRequest, db *sql.DB, tableName string) {
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

// Create or load a table (every table represnets one tree)
func initValueMap(db *sql.DB, tableName string) (bool, error) {
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

// commitChangesToDB stores the updated nodes to disk.
func (db *CacheDB) commitChangesToDB() error {
	db.updatedMux.Lock()
	defer db.updatedMux.Unlock()
	// string builder for query
	var sb strings.Builder

	// TODO(yongzhe): maybe update is more efficient?
	// replace the current (key, value) pair in DB; If exists, update it; If not, add one
	queryStr := "REPLACE into `map`.`" + db.tableName + "` (`key`, `value`) values "
	sb.WriteString(queryStr)

	isFirst := true
	// prepare queries
	for k, v := range db.updatedNodes {
		value := hex.EncodeToString(serializeBatch(v))
		key := hex.EncodeToString(k[:])
		if isFirst {
			sb.WriteString("('" + key + "', '" + value + "')")
			isFirst = false
		} else {
			sb.WriteString(",('" + key + "', '" + value + "')")
		}
	}
	sb.WriteString(";")

	fmt.Println("size of writes: ", len(db.updatedNodes))

	_, err := db.Store.Exec(sb.String())
	if err != nil {
		return fmt.Errorf("commit | Query | %w", err)
	}

	db.updatedNodes = make(map[Hash][][]byte)

	start := time.Now()
	if len(db.removedNode) != 0 {
		var deleteSB strings.Builder
		queryStr = "DELETE from `map`.`" + db.tableName + "` WHERE `key` IN ("
		deleteSB.WriteString(queryStr)

		isFirst = true
		for k := range db.removedNode {
			key := hex.EncodeToString(k[:])
			if isFirst {
				deleteSB.WriteString("'" + key + "'")
				isFirst = false
			} else {
				deleteSB.WriteString(",'" + key + "'")
			}
		}

		deleteSB.WriteString(");")

		fmt.Println("size of remove: ", len(db.removedNode))

		_, err := db.Store.Exec(deleteSB.String())
		if err != nil {
			return fmt.Errorf("commit | DELETE | %w", err)
		}

		db.removedNode = make(map[Hash][]byte)
	}
	end := time.Now()
	fmt.Println("time to delete nodes: ", end.Sub(start))
	return nil
}

// serializeBatch serialises the 2D [][]byte into a []byte for db
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
