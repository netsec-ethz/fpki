package db

import (
	"context"
)

// NOTE
// The project contains three tables:
// * Domain entries tables: the table to store domain materials.
// -- Key: hex-encoded of domain name hash: hex.EncodeToString(SHA256(domain name))
// -- Value: Serialised data of domain materials. Use Json to serialise the data structure.
// * Tree table: contains the Sparse Merkle Tree. Store the nodes of Sparse Merkle Tree
// * updates table: contains the domain hashes of the changed domains during this update.
//   updates table will be truncated after the Sparse Merkle Tree is updated.

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

// TableName: enum type of tables
// Currently two tables:
// - DomainEntries table: used to store domain materials(certificates, PC, RPC, etc.)
// - Tree table: store the SMT tree structure
type TableName int

const (
	DomainEntries TableName = iota
	Tree          TableName = iota
)

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

	// RetrieveTableRowsCount: Retrieve number of entries in updates table
	RetrieveTableRowsCount(ctx context.Context) (int, error)

	// UpdateKeyValuePairBatches: Update a list of key-value store
	UpdateKeyValuePairBatches(ctx context.Context, keyValuePairs []KeyValuePair, tableName TableName) (error, int)

	// DeleteKeyValuePairBatches: Delete a list of key-value store
	DeleteKeyValuePairBatches(ctx context.Context, keys []string, tableName TableName) error

	// InsertIgnoreKeyBatches: Insert a list of keys into the updates table. If key exists, ignore it.
	InsertIgnoreKeyBatches(ctx context.Context, keys []string) (int, error)

	// TruncateUpdatesTable: Truncate updates table
	TruncateUpdatesTable(ctx context.Context) error

	// DisableKeys: Disable keys for a table.
	DisableKeys() error

	//EnableKeys: Enable keys for a table.
	EnableKeys() error
}
