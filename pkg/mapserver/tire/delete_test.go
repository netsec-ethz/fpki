package trie

import (
	"database/sql"
	"fmt"
	"testing"

	_ "github.com/go-sql-driver/mysql"

	"github.com/stretchr/testify/require"
)

func TestTrieUpdate(t *testing.T) {
	db, err := sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/map?multiStatements=true")
	require.NoError(t, err, "db conn error")

	defer db.Close()
	smt, err := NewTrie(nil, Hasher, *db)

	smt.CacheHeightLimit = 0
	// Add data to empty trie
	keys := getFreshData(20, 32)
	values := getFreshData(20, 32)
	smt.Update(keys, values)
	err = smt.Commit()
	if err != nil {
		panic(err)
	}

	fmt.Println("updated nodes ", len(smt.db.updatedNodes))
	fmt.Println("live cache ", len(smt.db.liveCache))
	fmt.Println("delete node", len(smt.db.removedNode))

	newValues := getFreshData(20, 32)
	smt.Update(keys, newValues)

	err = smt.Commit()
	if err != nil {
		panic(err)
	}

	fmt.Println("updated nodes ", len(smt.db.updatedNodes))
	fmt.Println("live cache ", len(smt.db.liveCache))
	fmt.Println("delete node", len(smt.db.removedNode))

}
