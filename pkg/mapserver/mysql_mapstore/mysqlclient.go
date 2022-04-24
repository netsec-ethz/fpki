package mysql_mapstore

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"time"
)

// open db conn when needs to insert, query or delete
// TODO: open a consistent conn to db (maybe)

type MapSQLStore struct {
	tableName string
	dbUrl     string
	db        *sql.DB
}

// InvalidKeyError is thrown when a key that does not exist is being accessed.
type InvalidKeyError struct {
	Key []byte
}

func (e *InvalidKeyError) Error() string {
	return fmt.Sprintf("invalid key: %x", e.Key)
}

func InitMapSQLStore(dbUrl string, tableName string) (*MapSQLStore, error) {
	mapSQLStore := &MapSQLStore{
		tableName: tableName,
		dbUrl:     dbUrl,
	}

	db, err := sql.Open("mysql", mapSQLStore.dbUrl)
	if err != nil {
		return nil, err
	}

	mapSQLStore.db = db
	mapSQLStore.db.SetConnMaxLifetime(time.Minute * 3)
	mapSQLStore.db.SetMaxOpenConns(10)
	mapSQLStore.db.SetMaxIdleConns(10)

	err = mapSQLStore.createNewTable()
	if err != nil {
		return nil, err
	}

	return mapSQLStore, err
}

func (mapSQLStore *MapSQLStore) createNewTable() error {
	queryStr := "SELECT COUNT(*) FROM information_schema.tables  WHERE table_schema = 'map'  AND table_name = '" + mapSQLStore.tableName + "';"

	insert, err := mapSQLStore.db.Query(queryStr)
	if err != nil {
		return err
	}
	defer insert.Close()

	var tableIsExisted bool
	insert.Next()
	err = insert.Scan(&tableIsExisted)
	if err != nil {
		return err
	}

	if !tableIsExisted {
		//fmt.Println("hi I'm a new table")
		queryStr = "CREATE TABLE `map`.`" + mapSQLStore.tableName + "` (`key` VARCHAR(64) NOT NULL, `value` VARCHAR(4096) NOT NULL, PRIMARY KEY (`key`));"
		newTable, err := mapSQLStore.db.Query(queryStr)
		if err != nil {
			return err
		}
		defer newTable.Close()
	}
	return nil
}

func (mapSQLStore *MapSQLStore) Get(key []byte) ([]byte, error) {

	keyString := hex.EncodeToString(key)

	queryStr := "SELECT `value` FROM map.`" + mapSQLStore.tableName + "` WHERE `key` = '" + keyString + "';"
	insert, err := mapSQLStore.db.Query(queryStr)

	if err != nil {
		return nil, fmt.Errorf("Set | Query | %s", err.Error())
	}

	defer insert.Close()

	var value string
	insert.Next()
	err = insert.Scan(&value)
	if err != nil {
		return nil, &InvalidKeyError{Key: key}
	}

	result, err := hex.DecodeString(value)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (mapSQLStore *MapSQLStore) Set(key []byte, value []byte) error {

	keyString := hex.EncodeToString(key)
	valueString := hex.EncodeToString(value)

	//fmt.Println(keyString)

	queryStr := "INSERT INTO `map`.`" + mapSQLStore.tableName + "` (`key`, `value`) VALUES('" + keyString + "', '" + valueString + "') ON DUPLICATE KEY UPDATE value='" + valueString + "';"

	insert, err := mapSQLStore.db.Query(queryStr)

	if err != nil {
		fmt.Println(err)
		return fmt.Errorf("Set | Query | %s", err.Error())
	}

	defer insert.Close()
	return nil
}

func (mapSQLStore *MapSQLStore) Delete(key []byte) error {

	keyString := hex.EncodeToString(key)

	queryStr := "DELETE FROM `map`.`" + mapSQLStore.tableName + "` WHERE (`key` = '" + keyString + "');"

	insert, err := mapSQLStore.db.Query(queryStr)

	if err != nil {
		return fmt.Errorf("Set | Query | %s", err.Error())
	}

	defer insert.Close()

	return nil
}

func (mapSQLStore *MapSQLStore) FetchAll() error {
	db, err := sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/map")
	if err != nil {
		return err
	}
	queryStr := "SELECT * FROM map.628379840923_value;"
	insert, err := db.Query(queryStr)
	if err != nil {
		return fmt.Errorf("Set | Query | %s", err.Error())
	}
	defer insert.Close()

	return nil

}
