package mapserver

import (
	"database/sql"
	"encoding/hex"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
)

// DBAccessor: Struc which represents the DB accessor
type DBAccessor struct {
	db        *sql.DB
	tableName string
	dbUrl     string
}

// NodeID: Present one node in the PoI (Used in strategy 3)
type NodeID struct {
	Depth int
	ID    [32]byte
	Proof []byte
}

// InvalidKeyError is thrown when a key that does not exist is being accessed.
// Error type
type InvalidKeyError struct {
	Key []byte
}

// Error: Implement Error() interface
func (e *InvalidKeyError) Error() string {
	return fmt.Sprintf("invalid key: %x", e.Key)
}

// InitDBAccessor: Get a new DB accessor
func InitDBAccessor(dburl, tableName string) (*DBAccessor, error) {
	// open conn to db
	// TODO(yongzhe): here we can set some parameters for the db conn.
	db, err := sql.Open("mysql", dburl)
	if err != nil {
		return nil, fmt.Errorf("InitDBAccessor | Open | %w", err)
	}

	// load the table; If table does not exist, create a new one.
	err = loadTable(tableName, db)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("InitDBAccessor | loadTable | %w", err)
	}

	return &DBAccessor{
		db:        db,
		tableName: tableName,
		dbUrl:     dburl,
	}, nil
}

// Close: Close db conn
func (datastore *DBAccessor) Close() {
	datastore.db.Close()
}

func loadTable(tableName string, db *sql.DB) error {
	queryTableStr := "SELECT COUNT(*) FROM information_schema.tables  WHERE table_schema = 'map'  AND table_name = '" + tableName + "';"

	result, err := db.Query(queryTableStr)
	if err != nil {
		return fmt.Errorf("loadTable | SELECT COUNT(*) | %s", err.Error())
	}
	defer result.Close()

	// check if table exists
	var tableIsExisted bool
	result.Next()
	err = result.Scan(&tableIsExisted)
	if err != nil {
		return fmt.Errorf("loadTable | tableIsExisted | %s", err.Error())
	}

	// if table not exists -> create a new one
	if !tableIsExisted {
		fmt.Println("create a new table")
		// create a new table with two columns
		// key             VARCHAR(64)             Primary Key
		// value           VARCHAR(1024) (TODO: Use BLOB)
		createMapStr := "CREATE TABLE `map`.`" + tableName + "` (`key` VARCHAR(64) NOT NULL, `value` VARCHAR(1024) NOT NULL, PRIMARY KEY (`key`));"
		newTable, err := db.Query(createMapStr)
		if err != nil {
			return fmt.Errorf("loadTable | CREATE TABLE | %s", err.Error())
		}
		defer newTable.Close()
	}
	return nil
}

// Retrive: Retrive value according to key
func (sqlDataStore *DBAccessor) Retrive(leafHash [32]byte) ([]byte, []NodeID, error) {
	// encode the []byte
	keyString := hex.EncodeToString(leafHash[:])
	queryGetStr := "SELECT value FROM `map`.`" + sqlDataStore.tableName + "` WHERE `key` = '" + keyString + "';"

	result, err := sqlDataStore.db.Query(queryGetStr)
	if err != nil {
		return nil, nil, fmt.Errorf("Retrive | SELECT value | %s", err.Error())
	}
	defer result.Close()

	var valueString string
	hasResult := result.Next()
	if !hasResult {
		return nil, nil, &InvalidKeyError{Key: leafHash[:]}
	}

	err = result.Scan(&valueString)
	if err != nil {
		return nil, nil, fmt.Errorf("Retrive | Scan error | %s", err.Error())
	}

	value, err := hex.DecodeString(valueString)
	if err != nil {
		return nil, nil, fmt.Errorf("Retrive | DecodeString | %s", err.Error())
	}
	return value, nil, nil
}

// Update: Update value by key
func (sqlDataStore *DBAccessor) Update(leafHash [32]byte, leafContent []byte) error {
	keyString := hex.EncodeToString(leafHash[:])
	valueString := hex.EncodeToString(leafContent)

	queryStr := "REPLACE into `map`.`" + sqlDataStore.tableName + "` (`key`, `value`) values('" + keyString + "', '" + valueString + "');"
	result, err := sqlDataStore.db.Query(queryStr)
	if err != nil {
		return fmt.Errorf("Update | REPLACE into | %s", err.Error())
	}
	defer result.Close()

	return nil
}

// not implemented; not used for now
func (sqlDataStore *DBAccessor) Delete(key [32]byte) error {
	return nil
}
