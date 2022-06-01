package db

import (
	"context"
)

// FullID: Juan's data structure
type FullID [33]byte // first byte is depth -1 (root not allowed)

// keyValueResult: used in worker thread; in multi-thread read
type keyValueResult struct {
	Pairs []KeyValuePair
	Err   error
}

// KeyValuePair: key-value pair;
// key: hex-encoded of domain name hash: hex.EncodeToString(SHA256(domain name))
// TODO(yongzhe): change key to bytes
type KeyValuePair struct {
	Key   string
	Value []byte
}

// Conn: interface for db connection
type Conn interface {
	// Close closes the connection.
	Close() error

	// RetrieveValue returns the value associated with the node.
	RetrieveValue(ctx context.Context, id FullID) ([]byte, error)

	// RetrieveNode returns the value and the proof path (without the root) for a given node.
	// Since each one of the steps of the proof path has a fixed size, returning the path
	// as a slice is sufficient to know how many steps there were in the proof path.
	RetrieveNode(ctx context.Context, id FullID) ([]byte, []byte, error)

	// RetrieveOneKeyValuePair: Retrieve one key-value pair from table
	RetrieveOneKeyValuePair(ctx context.Context, id string, tableName TableName) (*KeyValuePair, error)

	// RetrieveKeyValuePairMultiThread: Retrieve a list of key-value pairs from DB. Multi-threaded
	RetrieveKeyValuePairMultiThread(ctx context.Context, id []string, numOfRoutine int, tableName TableName) ([]KeyValuePair, error)

	// RetrieveUpdatedDomainMultiThread: Retrieve all updated domain hashes from update table
	RetrieveUpdatedDomainMultiThread(ctx context.Context, perQueryLimit int) ([]string, error)

	// CountUpdates: Retrieve number of entries in updates table
	CountUpdates(ctx context.Context) (int, error)

	// UpdateKeyValuePairBatches: Update a list of key-value store
	UpdateKeyValues(ctx context.Context, keyValuePairs []KeyValuePair, tableName TableName) (error, int)

	// DeleteKeyValues: Delete a list of key-value store
	DeleteKeyValues(ctx context.Context, keys []string, tableName TableName) error

	// ReplaceKeys: Insert a list of keys into the updates table. If key exists, ignore it.
	ReplaceKeys(ctx context.Context, keys []string) (int, error)

	// TruncateUpdatesTable: Truncate updates table
	TruncateUpdatesTable(ctx context.Context) error
}
