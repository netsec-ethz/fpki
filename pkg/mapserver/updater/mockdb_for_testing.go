package updater

import (
	"context"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
)

type MockDB struct {
	treeTable          map[common.SHA256Output][]byte
	domainEntriesTable map[common.SHA256Output][]byte
	updatesTable       map[common.SHA256Output]struct{}
}

// newMockDB: return a new mock db
func newMockDB() *MockDB {
	return &MockDB{
		treeTable:          make(map[common.SHA256Output][]byte),
		domainEntriesTable: make(map[common.SHA256Output][]byte),
		updatesTable:       make(map[common.SHA256Output]struct{}),
	}
}

// Close closes the connection.
func (d *MockDB) Close() error { return nil }

func (d *MockDB) RetrieveOneKeyValuePairTreeStruc(ctx context.Context, id common.SHA256Output) (*db.KeyValuePair, error) {
	return &db.KeyValuePair{Key: id, Value: d.treeTable[id]}, nil
}

func (d *MockDB) RetrieveOneKeyValuePairDomainEntries(ctx context.Context, key common.SHA256Output) (*db.KeyValuePair, error) {
	return &db.KeyValuePair{Key: key, Value: d.domainEntriesTable[key]}, nil
}

// RetrieveKeyValuePairFromTreeStruc: Retrieve a list of key-value pairs from Tree tables. Used by SMT lib.
func (d *MockDB) RetrieveKeyValuePairTreeStruc(ctx context.Context, id []common.SHA256Output, numOfRoutine int) ([]db.KeyValuePair, error) {
	result := []db.KeyValuePair{}
	for _, key := range id {
		value, ok := d.treeTable[key]
		if !ok {
			continue
		}
		result = append(result, db.KeyValuePair{Key: key, Value: value})
	}
	return result, nil
}

// RetrieveKeyValuePairFromDomainEntries: Retrieve a list of domain entries
func (d *MockDB) RetrieveKeyValuePairDomainEntries(ctx context.Context, id []common.SHA256Output, numOfRoutine int) ([]db.KeyValuePair, error) {
	result := []db.KeyValuePair{}
	for _, key := range id {
		value, ok := d.domainEntriesTable[key]
		if !ok {
			continue
		}
		result = append(result, db.KeyValuePair{Key: key, Value: value})
	}
	return result, nil
}

func (d *MockDB) RetrieveUpdatedDomainHashesUpdates(ctx context.Context, perQueryLimit int) ([]common.SHA256Output, error) {
	result := []common.SHA256Output{}
	for k, _ := range d.updatesTable {
		result = append(result, k)
	}
	return result, nil
}

func (d *MockDB) GetCountOfUpdatesDomainsUpdates(ctx context.Context) (int, error) {
	return len(d.updatesTable), nil
}

func (d *MockDB) UpdateKeyValuesDomainEntries(ctx context.Context, keyValuePairs []db.KeyValuePair) (int64, error) {
	for _, pair := range keyValuePairs {
		d.domainEntriesTable[pair.Key] = pair.Value
	}

	return 0, nil
}

func (d *MockDB) UpdateKeyValuesTreeStruc(ctx context.Context, keyValuePairs []db.KeyValuePair) (int64, error) {
	for _, pair := range keyValuePairs {
		d.treeTable[pair.Key] = pair.Value
	}

	return 0, nil
}

func (d *MockDB) DeleteKeyValuesTreeStruc(ctx context.Context, keys []common.SHA256Output) (int64, error) {
	for _, key := range keys {
		delete(d.treeTable, key)
	}
	return 0, nil
}

func (d *MockDB) AddUpdatedDomainHashesUpdates(ctx context.Context, keys []common.SHA256Output) (int64, error) {
	for _, key := range keys {
		d.updatesTable[key] = empty
	}
	return 0, nil
}

func (d *MockDB) TruncateUpdatesTableUpdates(ctx context.Context) error {
	d.updatesTable = make(map[common.SHA256Output]struct{})
	return nil
}

//*********************************************************
//                 Not used
//*********************************************************

// RetrieveValue returns the value associated with the node.
func (d *MockDB) RetrieveValue(ctx context.Context, id db.FullID) ([]byte, error) { return nil, nil }

// RetrieveNode returns the value and the proof path (without the root) for a given node.
// Since each one of the steps of the proof path has a fixed size, returning the path
// as a slice is sufficient to know how many steps there were in the proof path.
func (d *MockDB) RetrieveNode(ctx context.Context, id db.FullID) ([]byte, []byte, error) {
	return nil, nil, nil
}
