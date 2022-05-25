package db

import (
	"context"
	"database/sql"
)

type FullID [33]byte // first byte is depth -1 (root not allowed)

type Conn interface {
	DB() *sql.DB
	// Close closes the connection.
	Close() error
	// RetrieveValue returns the value associated with the node.
	RetrieveValue(ctx context.Context, id FullID) ([]byte, error)
	// RetrieveNode returns the value and the proof path (without the root) for a given node.
	// Since each one of the steps of the proof path has a fixed size, returning the path
	// as a slice is sufficient to know how many steps there were in the proof path.
	RetrieveNode(ctx context.Context, id FullID) ([]byte, []byte, error)
	// FlattenSubtree flattens a subtee. It uses the flatten_subtree stored procedure for this.
	FlattenSubtree(ctx context.Context, id [33]byte, proofChain []byte) error
}
