package db

import "context"

type FullID [33]byte // first byte is depth -1 (root not allowed)

type KeyValueResult struct {
	Pairs []KeyValuePair
	Err   error
}

type KeyValuePair struct {
	Key   string
	Value []byte
}

type Conn interface {
	// Close closes the connection.
	Close() error
	// RetrieveValue returns the value associated with the node.
	RetrieveValue(ctx context.Context, id FullID) ([]byte, error)
	// RetrieveNode returns the value and the proof path (without the root) for a given node.
	// Since each one of the steps of the proof path has a fixed size, returning the path
	// as a slice is sufficient to know how many steps there were in the proof path.
	RetrieveNode(ctx context.Context, id FullID) ([]byte, []byte, error)

	RetrieveKeyValuePairMultiThread(ctx context.Context, id []string, goroutinesCount int) (*KeyValueResult, error)

	UpdateKeyValuePairBatches(ctx context.Context, keyValuePairs []KeyValuePair) error
}
