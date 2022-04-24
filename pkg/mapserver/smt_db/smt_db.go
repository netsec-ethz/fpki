package smt_db

import (
	"crypto/sha256"
	"fmt"
	smt "github.com/celestiaorg/smt"
	mysql_mapstore "github.com/netsec-ethz/fpki/pkg/mapserver/mysql_mapstore"
	"strconv"
)

// One sparse merkle tree
type Map_SMT struct {
	sparseMerkleTree *smt.SparseMerkleTree
	treeID           int64
	nodeStore        *mysql_mapstore.MapSQLStore
	valueStore       *mysql_mapstore.MapSQLStore
}

// init the SMT, given the root and treeID. If it's a new tree, root can be nil.
// TODO(Yongzhe): The "smt" lib does not provide root checking, when importing from an old tree.
// But if we store the root in the DB, normally this would not be an issue(or maybe?).
func InitSMT(treeID int64, root []byte) (*Map_SMT, error) {
	// load two map store
	nodeStore, isOldTree, err := mysql_mapstore.InitMapSQLStore("root:@tcp(127.0.0.1:3306)/map?multiStatements=true", strconv.FormatInt(treeID, 10)+"_node")
	if err != nil {
		return nil, fmt.Errorf("initSMT | nodeStore | %s", err.Error())
	}

	valueStore, _, err := mysql_mapstore.InitMapSQLStore("root:@tcp(127.0.0.1:3306)/map?multiStatements=true", strconv.FormatInt(treeID, 10)+"_value")
	if err != nil {
		return nil, fmt.Errorf("initSMT | valueStore | %s", err.Error())
	}

	// check if root is valid
	// TODO(Yongzhe): Some checking here maybe?
	if isOldTree && len(root) == 0 {
		return nil, fmt.Errorf("initSMT | valueStore | Oldtree needs a valid root")
	}

	var sparseMerkleTree *smt.SparseMerkleTree
	if isOldTree {
		sparseMerkleTree = smt.ImportSparseMerkleTree(nodeStore, valueStore, sha256.New(), root)
	} else {
		sparseMerkleTree = smt.NewSparseMerkleTree(nodeStore, valueStore, sha256.New())
	}

	return &Map_SMT{
		sparseMerkleTree: sparseMerkleTree,
		treeID:           treeID,
		nodeStore:        nodeStore,
		valueStore:       valueStore,
	}, nil
}

func (map_smt *Map_SMT) Update(key, value []byte) ([]byte, error) {
	return map_smt.sparseMerkleTree.Update(key, value)
}

func (map_smt *Map_SMT) Prove(key []byte) (smt.SparseMerkleProof, error) {
	return map_smt.sparseMerkleTree.Prove(key)
}

func (map_smt *Map_SMT) Root() []byte {
	return map_smt.sparseMerkleTree.Root()
}

func (map_smt *Map_SMT) SaveSMT() error {
	err := map_smt.nodeStore.SaveValueMapToDB()
	if err != nil {
		return fmt.Errorf("SaveSMT | SaveValueMapToDB | %s", err.Error())
	}
	err = map_smt.valueStore.SaveValueMapToDB()

	return err
}
