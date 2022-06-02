package db

import (
	"context"
)

// FullID: Key for faltten tree investigation
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

	// ************************************************************
	//              Function for Tree table
	// ************************************************************

	// RetrieveOneKeyValuePair_TreeStruc: Retrieve one key-value pair from Tree table.
	RetrieveOneKeyValuePair_TreeStruc(ctx context.Context, id string) (*KeyValuePair, error)

	// RetrieveKeyValuePair_TreeStruc: Retrieve a list of key-value pairs from Tree tables.
	RetrieveKeyValuePair_TreeStruc(ctx context.Context, id []string, numOfRoutine int) ([]KeyValuePair, error)

	// UpdateKeyValues_TreeStruc: Update a list of key-value pairs in Tree table
	UpdateKeyValues_TreeStruc(ctx context.Context, keyValuePairs []KeyValuePair) (error, int)

	// DeleteKeyValues_TreeStruc: Delete a list of key-value pairs in Tree table
	DeleteKeyValues_TreeStruc(ctx context.Context, keys []string) error

	// ************************************************************
	//             Function for DomainEntries table
	// ************************************************************

	// RetrieveKeyValuePair_DomainEntries: Retrieve a list of domain entries table
	RetrieveKeyValuePair_DomainEntries(ctx context.Context, id []string, numOfRoutine int) ([]KeyValuePair, error)

	// UpdateKeyValues_DomainEntries: Update a list of key-value pairs in domain entries table
	UpdateKeyValues_DomainEntries(ctx context.Context, keyValuePairs []KeyValuePair) (error, int)

	// ************************************************************
	//           Function for Updates table
	// ************************************************************

	// GetCountOfUpdatesDomains_Updates: Retrieve number of updated domains during this updates.
	GetCountOfUpdatesDomains_Updates(ctx context.Context) (int, error)

	// AddUpdatedDomainHashes_Updates: Add a list of hashes of updated domain into the updates table. If key exists, ignore it.
	AddUpdatedDomainHashes_Updates(ctx context.Context, keys []string) (int, error)

	// RetrieveUpdatedDomainHashes_Updates: Retrieve all updated domain hashes from update table
	RetrieveUpdatedDomainHashes_Updates(ctx context.Context, perQueryLimit int) ([]string, error)

	// TruncateUpdatesTable_Updates: Truncate updates table; Called after updating is finished
	TruncateUpdatesTable_Updates(ctx context.Context) error

	// ************************************************************
	//         Not used functions; Used for flatten tree
	// ************************************************************

	// RetrieveValue returns the value associated with the node.
	RetrieveValue(ctx context.Context, id FullID) ([]byte, error)

	// RetrieveNode returns the value and the proof path (without the root) for a given node.
	// Since each one of the steps of the proof path has a fixed size, returning the path
	// as a slice is sufficient to know how many steps there were in the proof path.
	RetrieveNode(ctx context.Context, id FullID) ([]byte, []byte, error)
}
