package main

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"time"

	"database/sql"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
)

func main() {
	clearTable()

	// test for tree table functions
	testTreeTable()

	// test for domain entries table functions
	testDomainEntriesTable()

	// test for updates table functions
	testUpdateTable()

	clearTable()
	fmt.Println("succeed")
}

// test tree table
func testTreeTable() {
	// *****************************************************************
	//                     open a db connection
	// *****************************************************************
	config := db.Configuration{
		Dsn: "root@tcp(localhost)/fpki",
		Values: map[string]string{
			"interpolateParams": "true", // 1 round trip per query
			"collation":         "binary",
		},
	}
	conn, err := db.Connect(&config)
	if err != nil {
		panic(err)
	}

	// *****************************************************************
	//                     insert into tree table
	// *****************************************************************
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	// insert key 1511 - 2012
	newKVPair := getKeyValuePair(1511, 2012, []byte("hi this is a test"))
	_, err = conn.UpdateKeyValuesTreeStruct(ctx, newKVPair)
	if err != nil {
		panic(err)
	}

	// insert key 2013 - 2055
	newKVPair = getKeyValuePair(2013, 2055, []byte("hi this is a test"))
	_, err = conn.UpdateKeyValuesTreeStruct(ctx, newKVPair)
	if err != nil {
		panic(err)
	}

	// insert key 2056 - 2155
	newKVPair = getKeyValuePair(2056, 2155, []byte("hi this is a test"))
	_, err = conn.UpdateKeyValuesTreeStruct(ctx, newKVPair)
	if err != nil {
		panic(err)
	}

	// insert key 2056 - 4555
	newKVPair = getKeyValuePair(2056, 4555, []byte("hi this is a test"))
	_, err = conn.UpdateKeyValuesTreeStruct(ctx, newKVPair)
	if err != nil {
		panic(err)
	}

	// *****************************************************************
	//              check if value is correctly inserted
	// *****************************************************************
	keys := getKeys(1511, 4555)
	prevKeySize := len(keys)
	result := []db.KeyValuePair{}

	for _, key := range keys {
		newResult, err := conn.RetrieveOneKeyValuePairTreeStruct(ctx, key)
		if err != nil && err != sql.ErrNoRows {
			panic(err)
		}
		if newResult != nil {
			// test of value if correctly stored and read
			if !bytes.Equal(newResult.Value, []byte("hi this is a test")) {
				panic("Tree Table Read test 1: Stored value is not correct")
			}
			result = append(result, *newResult)
		}
	}

	if len(keys) != len(result) {
		panic("Tree Table Read test 1: read result size error")
	}

	// query a larger range
	keys = getKeys(1011, 5555)
	result = []db.KeyValuePair{}

	for _, key := range keys {
		newResult, err := conn.RetrieveOneKeyValuePairTreeStruct(ctx, key)
		if err != nil && err != sql.ErrNoRows {
			panic(err)
		}
		if newResult != nil {
			// test of value if correctly stored and read
			if !bytes.Equal(newResult.Value, []byte("hi this is a test")) {
				panic("Tree Table Read test 2: Stored value is not correct")
			}
			result = append(result, *newResult)
		}
	}

	if prevKeySize != len(result) {
		panic("Tree Table Read test 2: read result size error")
	}

	// *****************************************************************
	//                       read empty keys
	// *****************************************************************
	keys = getKeys(11511, 14555)
	result = []db.KeyValuePair{}

	for _, key := range keys {
		newResult, err := conn.RetrieveOneKeyValuePairTreeStruct(ctx, key)
		if err != nil && err != sql.ErrNoRows {
			panic(err)
		}
		if newResult != nil {
			result = append(result, *newResult)
		}
	}

	if len(result) != 0 {
		panic("Tree Table Read test 3: read not inserted values")
	}

	// *****************************************************************
	//                       update keys
	// *****************************************************************
	newKVPair = getKeyValuePair(2056, 4555, []byte("new value"))
	_, err = conn.UpdateKeyValuesTreeStruct(ctx, newKVPair)
	if err != nil {
		panic(err)
	}

	// *****************************************************************
	//                 read updated key-value pairs
	// *****************************************************************
	keys = getKeys(2056, 4555)
	result = []db.KeyValuePair{}

	for _, key := range keys {
		newResult, err := conn.RetrieveOneKeyValuePairTreeStruct(ctx, key)
		if err != nil && err != sql.ErrNoRows {
			panic(err)
		}
		if newResult != nil {
			// test of value if correctly stored and read
			if !bytes.Equal(newResult.Value, []byte("new value")) {
				panic("Tree Table Read test 4: Stored value is not correct")
			}
			result = append(result, *newResult)
		}
	}

	if len(keys) != len(result) {
		panic("Tree Table Read test 4: read result size error")
	}

	// *****************************************************************
	//                       delete keys
	// *****************************************************************
	keys = getKeys(1000, 1200)
	affectDomainsCount, err := conn.DeleteKeyValuesTreeStruct(ctx, keys)
	if err != nil {
		panic(err)
	}

	if affectDomainsCount != 0 {
		panic("Tree Table Read test 5: affected number error (1000-1200)")
	}

	keys = getKeys(1511, 4222)
	affectDomainsCount, err = conn.DeleteKeyValuesTreeStruct(ctx, keys)
	if err != nil {
		panic(err)
	}
	if affectDomainsCount != int64(len(keys)) {
		panic("Tree Table Read test 5: affected number error (1511-4222)")
	}

	keys = getKeys(4223, 4555)
	affectDomainsCount, err = conn.DeleteKeyValuesTreeStruct(ctx, keys)
	if err != nil {
		panic(err)
	}
	if affectDomainsCount != int64(len(keys)) {
		panic("Tree Table Read test 5: affected number error (4223-4555)")
	}

	// *****************************************************************
	//                      read keys again
	// *****************************************************************
	keys = getKeys(1011, 5555)

	for _, key := range keys {
		newResult, err := conn.RetrieveOneKeyValuePairTreeStruct(ctx, key)
		if err != nil && err != sql.ErrNoRows {
			panic(err)
		}
		if newResult != nil {
			panic("Tree Table test 6: read deleted entry")
		}
	}

	// *****************************************************************
	//              Test Close()
	// *****************************************************************
	err = conn.Close()
	if err != nil {
		panic(err)
	}
}

// test tree table
func testDomainEntriesTable() {
	// *****************************************************************
	//                     open a db connection
	// *****************************************************************
	config := db.Configuration{
		Dsn: "root@tcp(localhost)/fpki",
		Values: map[string]string{
			"interpolateParams": "true", // 1 round trip per query
			"collation":         "binary",
		},
	}
	conn, err := db.Connect(&config)
	if err != nil {
		panic(err)
	}
	// *****************************************************************
	//                     insert into tree table
	// *****************************************************************
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	// insert key 1511 - 2012
	newKVPair := getKeyValuePair(1511, 2012, []byte("hi this is a test"))
	_, err = conn.UpdateKeyValuesDomainEntries(ctx, newKVPair)
	if err != nil {
		panic(err)
	}

	// insert key 2013 - 2055
	newKVPair = getKeyValuePair(2013, 2055, []byte("hi this is a test"))
	_, err = conn.UpdateKeyValuesDomainEntries(ctx, newKVPair)
	if err != nil {
		panic(err)
	}

	// insert key 2056 - 2155
	newKVPair = getKeyValuePair(2056, 2155, []byte("hi this is a test"))
	_, err = conn.UpdateKeyValuesDomainEntries(ctx, newKVPair)
	if err != nil {
		panic(err)
	}

	// insert key 2056 - 4555
	newKVPair = getKeyValuePair(2056, 4555, []byte("hi this is a test"))
	_, err = conn.UpdateKeyValuesDomainEntries(ctx, newKVPair)
	if err != nil {
		panic(err)
	}

	// *****************************************************************
	//              check if value is correctly inserted
	//              RetrieveOneKeyValuePairDomainEntries()
	// *****************************************************************
	keys := getKeys(1511, 4555)
	prevKeySize := len(keys)
	result := []db.KeyValuePair{}

	for _, key := range keys {
		newResult, err := conn.RetrieveOneKeyValuePairDomainEntries(ctx, key)
		if err != nil && err != sql.ErrNoRows {
			panic(err)
		}
		if newResult != nil {
			// test of value if correctly stored and read
			if !bytes.Equal(newResult.Value, []byte("hi this is a test")) {
				panic("Domain entries Table Read test 1: Stored value is not correct")
			}
			result = append(result, *newResult)
		}
	}

	if len(keys) != len(result) {
		panic("Domain entries Table Read test 1: read result size error")
	}

	// query a larger range
	keys = getKeys(1011, 5555)
	result = []db.KeyValuePair{}

	for _, key := range keys {
		newResult, err := conn.RetrieveOneKeyValuePairDomainEntries(ctx, key)
		if err != nil && err != sql.ErrNoRows {
			panic(err)
		}
		if newResult != nil {
			// test of value if correctly stored and read
			if !bytes.Equal(newResult.Value, []byte("hi this is a test")) {
				panic("Domain entries Table Read test 2: Stored value is not correct")
			}
			result = append(result, *newResult)
		}
	}

	if prevKeySize != len(result) {
		panic("Domain entries Table Read test 2: read result size error")
	}

	// *****************************************************************
	//              check if value is correctly inserted
	//              RetrieveKeyValuePairDomainEntries()
	// *****************************************************************
	result, err = conn.RetrieveKeyValuePairDomainEntries(ctx, keys, 10)
	if err != nil {
		panic(err)
	}

	if prevKeySize != len(result) {
		panic("Domain entries Table Read test 3: read result size error")
	}

	for _, newResult := range result {
		if !bytes.Equal(newResult.Value, []byte("hi this is a test")) {
			panic("Domain entries Table Read test 3: Stored value is not correct")
		}
	}

	// *****************************************************************
	//                       read empty keys
	// *****************************************************************
	keys = getKeys(11511, 14555)
	result = []db.KeyValuePair{}

	for _, key := range keys {
		newResult, err := conn.RetrieveOneKeyValuePairDomainEntries(ctx, key)
		if err != nil && err != sql.ErrNoRows {
			panic(err)
		}
		if newResult != nil {
			result = append(result, *newResult)
		}
	}

	if len(result) != 0 {
		panic("Domain entries Table Read test 4: read not inserted values")
	}

	// *****************************************************************
	//              Test Close()
	// *****************************************************************
	err = conn.Close()
	if err != nil {
		panic(err)
	}
}

// testUpdateTable: test if RetrieveTableRowsCount return correct number of entries.
func testUpdateTable() {
	// *****************************************************************
	//                     open a db connection
	// *****************************************************************
	config := db.Configuration{
		Dsn: "root@tcp(localhost)/fpki",
		Values: map[string]string{
			"interpolateParams": "true", // 1 round trip per query
			"collation":         "binary",
		},
	}
	conn, err := db.Connect(&config)
	if err != nil {
		panic(err)
	}

	// *****************************************************************
	//                        add some records
	// *****************************************************************
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	totalRecordsNum := 0

	keys := getKeys(100, 200)
	_, err = conn.AddUpdatedDomainHashesUpdates(ctx, keys)
	if err != nil {
		panic(err)
	}
	totalRecordsNum = totalRecordsNum + len(keys)

	keys = getKeys(333, 409)
	_, err = conn.AddUpdatedDomainHashesUpdates(ctx, keys)
	if err != nil {
		panic(err)
	}
	totalRecordsNum = totalRecordsNum + len(keys)

	// *****************************************************************
	//                        query updates
	// *****************************************************************
	numOfUpdates, err := conn.GetCountOfUpdatesDomainsUpdates(ctx)
	if err != nil {
		panic(err)
	}

	if numOfUpdates != totalRecordsNum {
		panic("Updates table test: missing some records")
	}

	keys, err = conn.RetrieveUpdatedDomainHashesUpdates(ctx, 1000)
	if len(keys) != numOfUpdates {
		panic("Updates table test: length not equal")
	}

	// *****************************************************************
	//                       truncate tables
	// *****************************************************************
	err = conn.TruncateUpdatesTableUpdates(ctx)
	if err != nil {
		panic(err)
	}

	// *****************************************************************
	//                      read records after truncation
	// *****************************************************************
	numOfUpdates, err = conn.GetCountOfUpdatesDomainsUpdates(ctx)
	if err != nil {
		panic(err)
	}
	if numOfUpdates != 0 {
		panic("Updates table test: table not truncated")
	}

	keys, err = conn.RetrieveUpdatedDomainHashesUpdates(ctx, 1000)
	if len(keys) != 0 {
		panic("Updates table test: read values after truncation")
	}

	// *****************************************************************
	//              Test Close()
	// *****************************************************************
	err = conn.Close()
	if err != nil {
		panic(err)
	}
}

func getKeyValuePair(startIdx, endIdx int, content []byte) []db.KeyValuePair {
	result := []db.KeyValuePair{}
	for i := startIdx; i <= endIdx; i++ {
		keyHash := common.SHA256Hash([]byte(strconv.Itoa(i)))
		keyHash32Bytes := [32]byte{}
		copy(keyHash32Bytes[:], keyHash)
		result = append(result, db.KeyValuePair{Key: keyHash32Bytes, Value: content})
	}
	return result
}

func getKeys(startIdx, endIdx int) []common.SHA256Output {
	result := []common.SHA256Output{}
	for i := startIdx; i <= endIdx; i++ {
		keyHash := common.SHA256Hash([]byte(strconv.Itoa(i)))
		keyHash32Bytes := [32]byte{}
		copy(keyHash32Bytes[:], keyHash)
		result = append(result, keyHash32Bytes)
	}
	return result
}

func clearTable() {
	db, err := sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/fpki?maxAllowedPacket=1073741824")
	if err != nil {
		panic(err)
	}

	_, err = db.Exec("TRUNCATE domainEntries;")
	if err != nil {
		panic(err)
	}

	_, err = db.Exec("TRUNCATE updates;")
	if err != nil {
		panic(err)
	}

	_, err = db.Exec("TRUNCATE tree;")
	if err != nil {
		panic(err)
	}

	err = db.Close()
	if err != nil {
		panic(err)
	}
}
