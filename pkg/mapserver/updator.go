package mapserver

import (
	"crypto/sha256"
	"fmt"
	"os"

	"github.com/celestiaorg/smt"
)

// Updator: Updator for the SMT
type Updator struct {
	tree       *smt.SparseMerkleTree
	nodeStore  *DBAccessorWraper
	valueStore *DBAccessorWraper
}

// NewUpdator: Get a new Updator
func NewUpdator(rootPath string) (*Updator, error) {
	root, err := os.ReadFile(rootPath)

	nodeStore, err := NewDBAccessorWraper("root:@tcp(127.0.0.1:3306)/map", "node")
	if err != nil {
		return nil, fmt.Errorf("NewUpdator | NewDBAccessorWraper | %w", err)
	}

	valueStore, err := NewDBAccessorWraper("root:@tcp(127.0.0.1:3306)/map", "value")
	if err != nil {
		return nil, fmt.Errorf("NewUpdator | NewDBAccessorWraper | %w", err)
	}

	var sparseMerkleTree *smt.SparseMerkleTree

	// if root file does not exist
	if len(root) == 0 {
		// new tre
		sparseMerkleTree = smt.NewSparseMerkleTree(nodeStore, valueStore, sha256.New())
	} else {
		fmt.Println("old table")
		// load an old tree
		sparseMerkleTree = smt.ImportSparseMerkleTree(nodeStore, valueStore, sha256.New(), root)
	}

	return &Updator{
		tree:       sparseMerkleTree,
		nodeStore:  nodeStore,
		valueStore: valueStore,
	}, nil
}

// Root: Get the root of the SMT
func (updator *Updator) Root() []byte {
	return updator.tree.Root()
}

// Close: Close two dbs
func (updator *Updator) Close() {
	updator.nodeStore.Close()
	updator.valueStore.Close()
}

// UpdateDomain: Update one domain's content(RPC, PC, etc)
func (updator *Updator) UpdateDomain(domainName string, domainContent []byte) error {
	_, err := updator.tree.Update([]byte(domainName), domainContent)
	if err != nil {
		return fmt.Errorf("UpdateDomain | Update | %w", err)
	}
	return nil
}
