package db

import (
	"context"
	"database/sql"

	"github.com/netsec-ethz/fpki/pkg/common"
)

const batchSize = 1000

// KeyValuePair: key-value pair
type KeyValuePair struct {
	Key   common.SHA256Output
	Value []byte
}

// Conn: interface for db connection
type Conn interface {
	DB() *sql.DB
	// Close closes the connection.
	Close() error

	// TruncateAllTables resets the DB to an initial state.
	TruncateAllTables() error

	// DisableIndexing stops the indexing in the table.
	DisableIndexing(table string) error

	// DisableIndexing starts the indexing in the table.
	EnableIndexing(table string) error

	// ************************************************************
	//              Function for Tree table
	// ************************************************************

	// RetrieveTreeNode: Retrieve one key-value pair from Tree table.
	RetrieveTreeNode(ctx context.Context, id common.SHA256Output) ([]byte, error)

	// UpdateTreeNodes: Update a list of key-value pairs in Tree table
	UpdateTreeNodes(ctx context.Context, keyValuePairs []*KeyValuePair) (int, error)

	// DeleteTreeNodes: Delete a list of key-value pairs in Tree table
	DeleteTreeNodes(ctx context.Context, keys []common.SHA256Output) (int, error)

	// ************************************************************
	//             Function for DomainEntries table
	// ************************************************************

	// RetrieveDomainEntry: Retrieve one key-value pair from domain entries table
	RetrieveDomainEntry(ctx context.Context, id common.SHA256Output) ([]byte, error)

	// RetrieveDomainEntries: Retrieve a list of domain entries table
	RetrieveDomainEntries(ctx context.Context, id []common.SHA256Output) ([]*KeyValuePair, error)

	// UpdateDomainEntries: Update a list of key-value pairs in domain entries table
	UpdateDomainEntries(ctx context.Context, keyValuePairs []*KeyValuePair) (int, error)

	// ************************************************************
	//           Function for Updates table
	// ************************************************************

	// CountUpdatedDomains: Retrieve number of updated domains during this updates.
	CountUpdatedDomains(ctx context.Context) (int, error) // TODO(juagargi) review usage

	// AddUpdatedDomains: Add a list of hashes of updated domain into the updates table. If key exists, ignore it.
	AddUpdatedDomains(ctx context.Context, keys []common.SHA256Output) (int, error)

	// TODO(yongzhe): investigate whether perQueryLimit is necessary
	// RetrieveUpdatedDomains: Retrieve all updated domain hashes from update table
	RetrieveUpdatedDomains(ctx context.Context, perQueryLimit int) ([]common.SHA256Output, error)

	// RemoveAllUpdatedDomains: Truncate updates table; Called after updating is finished
	RemoveAllUpdatedDomains(ctx context.Context) error

	// UpdatedDomains returns a channel of batches of updated domains.
	// A batch will have a implementation dependent size.
	// Each updated domain represents the SHA256 of the textual domain that was updated and
	// present in the `updates` table.
	UpdatedDomains() (chan []common.SHA256Output, chan error)
}
