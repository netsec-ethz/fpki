package db

import (
	"context"
	"errors"
)

type FullID [33]byte // first byte is depth -1 (root not allowed)

type KeyValueResult struct {
	Pairs []KeyValuePair
	Err   error
}

type KeyValuePair struct {
	Key   string
	Value []byte
}

type TableName int

const (
	DomainEntries TableName = iota
	Tree          TableName = iota
)

var ErrorResourceLocked = errors.New("resource locked")

type Conn interface {
	// Close closes the connection.
	Close() error
	// RetrieveValue returns the value associated with the node.
	RetrieveValue(ctx context.Context, id FullID) ([]byte, error)
	// RetrieveNode returns the value and the proof path (without the root) for a given node.
	// Since each one of the steps of the proof path has a fixed size, returning the path
	// as a slice is sufficient to know how many steps there were in the proof path.
	RetrieveNode(ctx context.Context, id FullID) ([]byte, []byte, error)

	RetrieveOneKeyValuePair(ctx context.Context, id string, tableName TableName) (*KeyValuePair, error)

	RetrieveKeyValuePairMultiThread(ctx context.Context, id []string, numOfRoutine int, tableName TableName) ([]KeyValuePair, error)

	RetrieveUpdatedDomainMultiThread(ctx context.Context, perQueryLimit int) ([]string, error)

	RetrieveTableRowsCount(ctx context.Context) (int, error)

	UpdateKeyValuePairBatches(ctx context.Context, keyValuePairs []KeyValuePair, tableName TableName) (error, int)

	DeleteKeyValuePairBatches(ctx context.Context, keys []string, tableName TableName) error

	InsertIgnoreKeyBatches(ctx context.Context, keys []string) (int, error)

	TruncateUpdatesTable(ctx context.Context) error

	DisableKeys() error

	EnableKeys() error
}
