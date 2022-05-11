package trie

import (
	"database/sql"
	"fmt"
	"testing"

	_ "github.com/go-sql-driver/mysql"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTrieUpdateWithSameKeys: Update key-value with same keys and different values. The size of nodes in the db should not chaned.
// It's a bug in the previous implementation, and I fixed it.
func TestTrieUpdateWithSameKeys(t *testing.T) {
	db, err := sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/map?multiStatements=true")
	require.NoError(t, err, "db conn error")

	err = dropTestTable(db)
	require.NoError(t, err, "dropTestTable error")

	smt, err := NewTrie(nil, Hasher, *db, "deleteTest")

	smt.CacheHeightLimit = 0
	// Add 10000 key-value pair
	keys := getFreshData(10000, 32)
	values := getFreshData(10000, 32)
	smt.Update(keys, values)
	err = smt.Commit()
	require.NoError(t, err, "Commit error")

	prevCacheSize := len(smt.db.liveCache)
	prevDBSize, err := getDbEntries(db)
	require.NoError(t, err, "query size error")

	fmt.Println("updated nodes ", len(smt.db.updatedNodes))
	fmt.Println("live cache ", len(smt.db.liveCache))
	fmt.Println("delete node", len(smt.db.removedNode))
	fmt.Println("table size", prevDBSize)

	// get 10000 new values
	newValues := getFreshData(10000, 32)
	smt.Update(keys, newValues)

	err = smt.Commit()
	require.NoError(t, err, "Commit error")

	newCacheSize := len(smt.db.liveCache)
	newDBSize, err := getDbEntries(db)
	require.NoError(t, err, "query size error")

	fmt.Println("updated nodes ", len(smt.db.updatedNodes))
	fmt.Println("live cache ", len(smt.db.liveCache))
	fmt.Println("delete node", len(smt.db.removedNode))
	fmt.Println("table size", newDBSize)

	// size of db should not change, because keys don't change
	assert.Equal(t, prevCacheSize, newCacheSize, "caache size not equal")
	assert.Equal(t, prevDBSize, newDBSize, "db size not equal")

	smt.Close()
}

// get number of rows in the table
func getDbEntries(db *sql.DB) (int, error) {
	queryStr := "SELECT COUNT(*) FROM map.deleteTest;"

	var number int
	err := db.QueryRow(queryStr).Scan(&number)
	if err != nil {
		return 0, fmt.Errorf("getDbEntries | SELECT COUNT(*) | %w", err)
	}

	return number, nil
}

func dropTestTable(db *sql.DB) error {
	queryStr := "DROP TABLE `map`.`deleteTest`;"

	_, err := db.Exec(queryStr)
	if err != nil && err.Error() != "Error 1051: Unknown table 'map.deletetest'" {
		return fmt.Errorf("dropTestTable | DROP | %w", err)
	}

	return nil
}
