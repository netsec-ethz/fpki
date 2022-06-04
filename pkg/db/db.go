package db

import (
	"context"

	"github.com/netsec-ethz/fpki/pkg/common"
)

const batchSize = 1000

// FullID: Key for flatten tree investigation
type FullID [33]byte // first byte is depth -1 (root not allowed)

// keyValueResult: used in worker thread; in multi-thread read
type keyValueResult struct {
	Pairs []KeyValuePair
	Err   error
}

// KeyValuePair: key-value pair;
type KeyValuePair struct {
	Key   common.SHA256Output
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
	RetrieveOneKeyValuePairTreeStruc(ctx context.Context, id common.SHA256Output) (*KeyValuePair, error)

	// RetrieveKeyValuePair_TreeStruc: Retrieve a list of key-value pairs from Tree tables.
	RetrieveKeyValuePairTreeStruc(ctx context.Context, id []common.SHA256Output, numOfRoutine int) ([]KeyValuePair, error)

	// UpdateKeyValues_TreeStruc: Update a list of key-value pairs in Tree table
	UpdateKeyValuesTreeStruc(ctx context.Context, keyValuePairs []KeyValuePair) (error, int)

	// DeleteKeyValues_TreeStruc: Delete a list of key-value pairs in Tree table
	DeleteKeyValuesTreeStruc(ctx context.Context, keys []common.SHA256Output) error

	// ************************************************************
	//             Function for DomainEntries table
	// ************************************************************

	// RetrieveOneKeyValuePairDomainEntries: Retrieve one key-value pair from domain entries table
	RetrieveOneKeyValuePairDomainEntries(ctx context.Context, id common.SHA256Output) (*KeyValuePair, error)

	// RetrieveKeyValuePair_DomainEntries: Retrieve a list of domain entries table
	RetrieveKeyValuePairDomainEntries(ctx context.Context, id []common.SHA256Output, numOfRoutine int) ([]KeyValuePair, error)

	// UpdateKeyValues_DomainEntries: Update a list of key-value pairs in domain entries table
	UpdateKeyValuesDomainEntries(ctx context.Context, keyValuePairs []KeyValuePair) (error, int)

	// ************************************************************
	//           Function for Updates table
	// ************************************************************

	// GetCountOfUpdatesDomains_Updates: Retrieve number of updated domains during this updates.
	GetCountOfUpdatesDomainsUpdates(ctx context.Context) (int, error)

	// AddUpdatedDomainHashes_Updates: Add a list of hashes of updated domain into the updates table. If key exists, ignore it.
	AddUpdatedDomainHashesUpdates(ctx context.Context, keys []common.SHA256Output) (int, error)

	// TODO(yongzhe): investigate whether perQueryLimit is necessary
	// RetrieveUpdatedDomainHashes_Updates: Retrieve all updated domain hashes from update table
	RetrieveUpdatedDomainHashesUpdates(ctx context.Context, perQueryLimit int) ([]common.SHA256Output, error)

	// TruncateUpdatesTable_Updates: Truncate updates table; Called after updating is finished
	TruncateUpdatesTableUpdates(ctx context.Context) error

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
