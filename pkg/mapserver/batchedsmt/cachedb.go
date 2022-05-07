package batchedsmt

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

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
	cachedNodes map[Hash][][]byte

	// cacheMux is a lock for cachedNodes
	cacheMux sync.RWMutex

	// updatedNodes that have will be flushed to disk
	updatedNodes map[Hash][][]byte

	// updatedMux is a lock for updatedNodes
	updatedMux sync.RWMutex

	// lock for CacheDB
	lock sync.RWMutex

	// dbConn is the conn to mysql db
	dbConn *sql.DB

	// Client is the channel for user input; Used to get read request from client
	ClientInput chan ReadRequest
}

// NewCacheDB: return a cached db
func NewCacheDB(store *sql.DB) (*CacheDB, error) {
	// check if the table exists
	// if not, create a new one
	_, err := initValueMap(store)
	if err != nil {
		return nil, fmt.Errorf("NewCacheDB | initValueMap | %w", err)
	}

	// channel for the client input
	clientInput := make(chan ReadRequest)

	return &CacheDB{
		cachedNodes:  make(map[Hash][][]byte),
		updatedNodes: make(map[Hash][][]byte),
		dbConn:       store,
		ClientInput:  clientInput,
	}, nil
}

// Start: creates workers and starts the worker distributor thread,
func (db *CacheDB) Start() {
	workerChan := make(chan ReadRequest)
	for i := 0; i < 10; i++ {
		go workerThread(workerChan, db.dbConn)
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
func workerThread(workerChan chan ReadRequest, db *sql.DB) {
	for {
		select {
		case newRequest := <-workerChan:
			readResult := ReadResult{}

			keyString := hex.EncodeToString(newRequest.key[:])
			queryGetStr := "SELECT value FROM `map`.`cacheStore` WHERE `key` = '" + keyString + "';"

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
func initValueMap(db *sql.DB) (bool, error) {
	// query to check if table exists
	// defeult db schema = 'map'
	queryTableStr := "SELECT COUNT(*) FROM information_schema.tables  WHERE table_schema = 'map'  AND table_name = 'cacheStore';"

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
		createMapStr := "CREATE TABLE `map`.`cacheStore` (`key` VARCHAR(128) NOT NULL, `value` VARCHAR(4096) NOT NULL, PRIMARY KEY (`key`));"
		newTable, err := db.Query(createMapStr)
		if err != nil {
			return false, fmt.Errorf("initValueMap | CREATE TABLE | %w", err)
		}
		defer newTable.Close()
	}
	return tableIsExisted, nil
}

// writeCachedDataToDB stores the updated nodes to disk.
func (db *CacheDB) writeCachedDataToDB() error {
	db.updatedMux.Lock()
	defer db.updatedMux.Unlock()
	// string builder for query
	var sb strings.Builder

	// TODO(yongzhe): maybe update is more efficient?
	// replace the current (key, value) pair in DB; If exists, update it; If not, add one
	queryStr := "REPLACE into `map`.`cacheStore` (`key`, `value`) values "
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

	// TODO(yongzhe): wrap the error later
	result, err := db.dbConn.Query(sb.String())
	if err != nil {
		return fmt.Errorf("commit | Query | %w", err)
	}
	defer result.Close()
	return nil
}
