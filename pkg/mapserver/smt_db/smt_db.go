package smt_db

import (
	"crypto/sha256"
	"fmt"
	smt "github.com/celestiaorg/smt"
	mysql_mapstore "github.com/netsec-ethz/fpki/pkg/mapserver/mysql_mapstore"
	"strconv"
)

type Map_SMT struct {
	smt    *smt.SparseMerkleTree
	treeID int64
}

func InitSMT(treeID int64) (*Map_SMT, error) {
	nodeStore, err := mysql_mapstore.InitMapSQLStore("root:@tcp(127.0.0.1:3306)/map", strconv.FormatInt(treeID, 10)+"_node")
	if err != nil {
		return nil, fmt.Errorf("initSMT | nodeStore | %s", err.Error())
	}

	valueStore, err := mysql_mapstore.InitMapSQLStore("root:@tcp(127.0.0.1:3306)/map", strconv.FormatInt(treeID, 10)+"_value")
	if err != nil {
		return nil, fmt.Errorf("initSMT | valueStore | %s", err.Error())
	}

	smt := smt.NewSparseMerkleTree(nodeStore, valueStore, sha256.New())

	return &Map_SMT{
		smt:    smt,
		treeID: treeID,
	}, nil
}

func (map_smt *Map_SMT) Update(key, value []byte) ([]byte, error) {
	return map_smt.smt.Update(key, value)
}

func (map_smt *Map_SMT) Prove(key []byte) (smt.SparseMerkleProof, error) {
	return map_smt.smt.Prove(key)
}

func (map_smt *Map_SMT) Root() []byte {
	return map_smt.smt.Root()
}
