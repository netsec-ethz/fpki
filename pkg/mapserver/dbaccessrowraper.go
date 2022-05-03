package mapserver

import (
	"fmt"
)

// DBAccessorWraper: Wraper for SMT lib. It's just a simple key-value store.
// SMT lib needs to implement three interfaces:
//        GET()
//        Set()
//        Delete()
type DBAccessorWraper struct {
	dbAccessor *DBAccessor
}

// NewDBAccessorWraper: Get a new DB Accessor wraper
func NewDBAccessorWraper(dburl, tableName string) (*DBAccessorWraper, error) {
	// init a DB accessor
	dbAccessor, err := InitDBAccessor(dburl, tableName)
	if err != nil {
		return nil, fmt.Errorf("NewDBAccessorWraper | InitDBAccessor | %w", err)
	}

	// wrap it
	return &DBAccessorWraper{
		dbAccessor: dbAccessor,
	}, nil
}

// Close: Close the db connection
func (dbAccessorWraper *DBAccessorWraper) Close() {
	dbAccessorWraper.dbAccessor.Close()
}

// Get: Get the value by key
func (wraper *DBAccessorWraper) Get(key []byte) ([]byte, error) {
	// key should be 32 bytes
	if len(key) != 32 {
		return nil, fmt.Errorf("DBAccessorWraper | Get | Key length error")
	}

	var leafHash [32]byte
	copy(leafHash[:], key[:])

	// use the DB accessor to query the result
	result, _, err := wraper.dbAccessor.Retrive(leafHash)
	if err != nil {
		return nil, fmt.Errorf("DBAccessorWraper | Get | Retrive | %w", err)
	}
	return result, nil
}

// Set: Set the value by key
func (wraper *DBAccessorWraper) Set(key []byte, value []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("DBAccessorWraper | Set | Key length error")
	}

	var leafHash [32]byte
	copy(leafHash[:], key[:])

	// use the DB accessor to set the result
	err := wraper.dbAccessor.Update(leafHash, value)
	if err != nil {
		return fmt.Errorf("DBAccessorWraper | Set | Update | %w", err)
	}
	return nil
}

// Delete: Delete value by key
func (wraper *DBAccessorWraper) Delete(key []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("DBAccessorWraper | Delete | Key length error")
	}

	var leafHash [32]byte
	copy(leafHash[:], key[:])

	err := wraper.dbAccessor.Delete(leafHash)
	if err != nil {
		return fmt.Errorf("DBAccessorWraper | Delete | Delete | %w", err)
	}
	return nil
}
