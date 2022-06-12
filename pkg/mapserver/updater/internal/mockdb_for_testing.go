package internal

import (
	"context"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
)

var empty struct{}

// MockDB: mock db is a memory store to simulate the db.
type MockDB struct {
	TreeTable          map[common.SHA256Output][]byte
	DomainEntriesTable map[common.SHA256Output][]byte
	UpdatesTable       map[common.SHA256Output]struct{}
}

// newMockDB: return a new mock db
func NewMockDB() *MockDB {
	return &MockDB{
		TreeTable:          make(map[common.SHA256Output][]byte),
		DomainEntriesTable: make(map[common.SHA256Output][]byte),
		UpdatesTable:       make(map[common.SHA256Output]struct{}),
	}
}

// Close closes the connection.
func (d *MockDB) Close() error { return nil }

func (d *MockDB) RetrieveOneKeyValuePairTreeStruc(ctx context.Context, id common.SHA256Output) (*db.KeyValuePair, error) {
	return &db.KeyValuePair{Key: id, Value: d.TreeTable[id]}, nil
}

func (d *MockDB) RetrieveOneKeyValuePairDomainEntries(ctx context.Context, key common.SHA256Output) (*db.KeyValuePair, error) {
	return &db.KeyValuePair{Key: key, Value: d.DomainEntriesTable[key]}, nil
}

func (d *MockDB) RetrieveKeyValuePairTreeStruc(ctx context.Context, id []common.SHA256Output,
	numOfRoutine int) ([]db.KeyValuePair, error) {
	result := []db.KeyValuePair{}
	for _, key := range id {
		value, ok := d.TreeTable[key]
		if !ok {
			continue
		}
		result = append(result, db.KeyValuePair{Key: key, Value: value})
	}
	return result, nil
}

func (d *MockDB) RetrieveKeyValuePairDomainEntries(ctx context.Context, id []common.SHA256Output,
	numOfRoutine int) ([]db.KeyValuePair, error) {
	result := []db.KeyValuePair{}
	for _, key := range id {
		value, ok := d.DomainEntriesTable[key]
		if !ok {
			continue
		}
		result = append(result, db.KeyValuePair{Key: key, Value: value})
	}
	return result, nil
}

func (d *MockDB) RetrieveUpdatedDomainHashesUpdates(ctx context.Context, perQueryLimit int) ([]common.SHA256Output, error) {
	result := []common.SHA256Output{}
	for k := range d.UpdatesTable {
		result = append(result, k)
	}
	return result, nil
}

func (d *MockDB) GetCountOfUpdatesDomainsUpdates(ctx context.Context) (int, error) {
	return len(d.UpdatesTable), nil
}

func (d *MockDB) UpdateKeyValuesDomainEntries(ctx context.Context, keyValuePairs []db.KeyValuePair) (int64, error) {
	for _, pair := range keyValuePairs {
		d.DomainEntriesTable[pair.Key] = pair.Value
	}

	return 0, nil
}

func (d *MockDB) UpdateKeyValuesTreeStruc(ctx context.Context, keyValuePairs []db.KeyValuePair) (int64, error) {
	for _, pair := range keyValuePairs {
		d.TreeTable[pair.Key] = pair.Value
	}

	return 0, nil
}

func (d *MockDB) DeleteKeyValuesTreeStruc(ctx context.Context, keys []common.SHA256Output) (int64, error) {
	for _, key := range keys {
		delete(d.TreeTable, key)
	}
	return 0, nil
}

func (d *MockDB) AddUpdatedDomainHashesUpdates(ctx context.Context, keys []common.SHA256Output) (int64, error) {
	for _, key := range keys {
		d.UpdatesTable[key] = empty
	}
	return 0, nil
}

func (d *MockDB) TruncateUpdatesTableUpdates(ctx context.Context) error {
	d.UpdatesTable = make(map[common.SHA256Output]struct{})
	return nil
}

//*********************************************************
//                 Not used
//*********************************************************

func (d *MockDB) RetrieveValue(ctx context.Context, id db.FullID) ([]byte, error) { return nil, nil }

func (d *MockDB) RetrieveNode(ctx context.Context, id db.FullID) ([]byte, []byte, error) {
	return nil, nil, nil
}
