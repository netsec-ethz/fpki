package batchedsmt

import (
	"database/sql"
	"testing"

	_ "github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/require"
)

func TestReloadTree(t *testing.T) {
	db, err := sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/map?multiStatements=true")
	require.NoError(t, err, "db conn error")
	db.SetMaxOpenConns(50)

	smt, err := NewSMT(nil, Hasher, db)
	require.NoError(t, err, "smt creation error")

	// Add data to empty trie
	keys := getFreshData(10000, 32)
	values := getFreshData(10000, 32)
	smt.Update(keys, values)
	smt.StoreUpdatedNode()
	db.Close()

	root := smt.Root

	db_, err := sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/map?multiStatements=true")
	if err != nil {
		t.Fatal("failed to init db %w", err)
	}
	defer db.Close()
	smt_, err := NewSMT(root, Hasher, db_)
	require.NoError(t, err, "smt creation error")

	for i, key := range keys {
		ap, _ := smt_.MerkleProof(key)
		if !VerifyMerkleProof(smt_.Root, ap, key, values[i]) {
			t.Fatalf("failed to verify inclusion proof")
		}
	}

	emptyKey := Hasher([]byte("non-member"))
	ap, _ := smt_.MerkleProof(emptyKey)
	if !VerifyMerkleProof(smt_.Root, ap, emptyKey, DefaultLeaf) {
		t.Fatalf("failed to verify non inclusion proof")
	}
	db_.Close()
}
