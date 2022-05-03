package mapserver

import (
	"crypto/sha256"
	"fmt"
	"os"

	"github.com/celestiaorg/smt"
)

// Responder: Responsible for serving the Proof for clients
type Responder struct {
	tree       *smt.SparseMerkleTree
	nodeStore  *DBAccessorWraper
	valueStore *DBAccessorWraper
}

// QueryResponse: Response from QueryDomain()
type QueryResponse struct {
	DomainName    string
	DomainContent []byte
	Proof         smt.SparseMerkleProof
	Root          []byte
	MapSig        []byte
}

// NewResponder: Get a new Responder
func NewResponder(rootPath string) (*Responder, error) {
	root, err := os.ReadFile(rootPath)

	nodeStore, err := NewDBAccessorWraper("root:@tcp(127.0.0.1:3306)/map", "node")
	if err != nil {
		return nil, fmt.Errorf("NewResponder | NewDBAccessorWraper | %w", err)
	}

	valueStore, err := NewDBAccessorWraper("root:@tcp(127.0.0.1:3306)/map", "value")
	if err != nil {
		return nil, fmt.Errorf("NewResponder | NewDBAccessorWraper | %w", err)
	}

	var sparseMerkleTree *smt.SparseMerkleTree

	// if root does not exist -> it's a new tree
	if len(root) == 0 {
		sparseMerkleTree = smt.NewSparseMerkleTree(nodeStore, valueStore, sha256.New())
	} else {
		fmt.Println("old table")
		// Load an old tree
		sparseMerkleTree = smt.ImportSparseMerkleTree(nodeStore, valueStore, sha256.New(), root)
	}

	return &Responder{
		tree:       sparseMerkleTree,
		nodeStore:  nodeStore,
		valueStore: valueStore,
	}, nil
}

// Close: Close two dbs
func (responder *Responder) Close() {
	responder.nodeStore.Close()
	responder.valueStore.Close()
}

// Root: Get root of SMT
func (responder *Responder) Root() []byte {
	return responder.tree.Root()
}

// QueryDomain: Return PoI, STH and content of one domain.
func (responder *Responder) QueryDomain(domainName string) (*QueryResponse, error) {
	domainContent, err := responder.tree.Get([]byte(domainName))
	if err != nil {
		return nil, fmt.Errorf("QueryDomain | Get domain content | %w", err)
	}

	proof, err := responder.tree.Prove([]byte(domainName))
	if err != nil {
		return nil, fmt.Errorf("QueryDomain | Prove | %w", err)
	}

	root := responder.tree.Root()

	return &QueryResponse{
		DomainName:    domainName,
		DomainContent: domainContent,
		Root:          root,
		Proof:         proof,
		MapSig:        []byte{},
	}, nil
}
