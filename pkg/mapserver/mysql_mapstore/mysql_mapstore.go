package mysql_mapstore

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"strings"
)

// MapSQLStore represents all the entries from one table
// It records the (key, value) pairs of one specific Sparse Merkle Tree
// tableName represents the treeID, normally it will be treeID_node or treeID_value
type MapSQLStore struct {
	// used to read or write to DB
	tableName string
	dbUrl     string

	// map[key] -> value
	valueMap map[string][]byte
}

// InvalidKeyError is thrown when a key that does not exist is being accessed.
// Error type
type InvalidKeyError struct {
	Key []byte
}

func (e *InvalidKeyError) Error() string {
	return fmt.Sprintf("invalid key: %x", e.Key)
}

// init map stire
// Read key-value map from DB
func InitMapSQLStore(dbUrl string, tableName string) (*MapSQLStore, bool, error) {
	mapSQLStore := &MapSQLStore{
		tableName: tableName,
		dbUrl:     dbUrl,
		valueMap:  make(map[string][]byte),
	}

	// initValueMap() will create or load one table; If table exists, isOldTree will be true
	isOldTree, err := mapSQLStore.initValueMap()
	if err != nil {
		return nil, false, err
	}

	return mapSQLStore, isOldTree, err
}

// Create or load a table (every table represnets one tree)
func (mapSQLStore *MapSQLStore) initValueMap() (bool, error) {
	// open db conn
	db, err := sql.Open("mysql", mapSQLStore.dbUrl)
	if err != nil {
		return false, fmt.Errorf("initValueMap | Open DB | %s", err.Error())
	}
	defer db.Close()

	// query to check if table exists
	// defeult db schema = 'map'
	queryTableStr := "SELECT COUNT(*) FROM information_schema.tables  WHERE table_schema = 'map'  AND table_name = '" + mapSQLStore.tableName + "';"

	result, err := db.Query(queryTableStr)
	if err != nil {
		return false, fmt.Errorf("initValueMap | SELECT COUNT(*) | %s", err.Error())
	}
	defer result.Close()

	// check if table exists
	var tableIsExisted bool
	result.Next()
	err = result.Scan(&tableIsExisted)
	if err != nil {
		return false, fmt.Errorf("initValueMap | tableIsExisted | %s", err.Error())
	}

	var key string
	var value string

	// if table not exists -> this is a new tree (treeID does not exist)
	if !tableIsExisted {
		// create a new table with two columns
		// key             VARCHAR(64)             Primary Key
		// value           VARCHAR(4096)
		createMapStr := "CREATE TABLE `map`.`" + mapSQLStore.tableName + "` (`key` VARCHAR(64) NOT NULL, `value` VARCHAR(4096) NOT NULL, PRIMARY KEY (`key`));"
		newTable, err := db.Query(createMapStr)
		if err != nil {
			return false, fmt.Errorf("initValueMap | CREATE TABLE | %s", err.Error())
		}

		defer newTable.Close()
	} else {
		// read all the data from db
		queryAllStr := "SELECT * FROM `map`.`" + mapSQLStore.tableName + "`"
		allEntries, err := db.Query(queryAllStr)
		if err != nil {
			return false, fmt.Errorf("initValueMap | SELECT * | %s", err.Error())
		}

		for allEntries.Next() {
			// parse the value
			err = allEntries.Scan(&key, &value)
			if err != nil {
				return false, fmt.Errorf("initValueMap | results.Scan | %s", err.Error())
			}

			// value and key are hexadecimal encoded
			valueBytes, err := hex.DecodeString(value)
			if err != nil {
				return false, fmt.Errorf("initValueMap | DecodeString | %s", err.Error())
			}

			keyBytes, err := hex.DecodeString(key)
			if err != nil {
				return false, fmt.Errorf("initValueMap | DecodeString | %s", err.Error())
			}

			// add the new entry to the map
			mapSQLStore.valueMap[string(keyBytes)] = valueBytes
		}
	}
	return tableIsExisted, nil
}

// save current map to DB
func (mapSQLStore *MapSQLStore) SaveValueMapToDB() error {
	// open a connection
	db, err := sql.Open("mysql", mapSQLStore.dbUrl)
	if err != nil {
		return fmt.Errorf("initValueMap | Open DB | %s", err.Error())
	}
	defer db.Close()

	// string builder for query
	var sb strings.Builder

	// combine multiple queries
	for k, v := range mapSQLStore.valueMap {
		value := hex.EncodeToString(v)
		key := hex.EncodeToString([]byte(k))

		// replace the current (key, value) pair in DB; If exists, update it; If not, add one
		sb.WriteString("REPLACE into `map`.`" + mapSQLStore.tableName + "` (`key`, `value`) values('" + key + "', '" + value + "');")
	}

	result, err := db.Query(sb.String())
	if err != nil {
		return fmt.Errorf("initValueMap | UPDATE MAP | %s", err.Error())
	}

	defer result.Close()
	return nil
}

// Implementations of "MapStore" interface
func (mapSQLStore *MapSQLStore) Get(key []byte) ([]byte, error) {
	if value, ok := mapSQLStore.valueMap[string(key)]; ok {
		return value, nil
	}
	return nil, &InvalidKeyError{Key: key}
}

func (mapSQLStore *MapSQLStore) Set(key []byte, value []byte) error {
	mapSQLStore.valueMap[string(key)] = value
	return nil
}

func (mapSQLStore *MapSQLStore) Delete(key []byte) error {
	_, ok := mapSQLStore.valueMap[string(key)]
	if ok {
		delete(mapSQLStore.valueMap, string(key))
		return nil
	}
	return &InvalidKeyError{Key: key}
}

// for debuging
func (mapSQLStore *MapSQLStore) GetSizeOfMap() int {
	return len(mapSQLStore.valueMap)
}
