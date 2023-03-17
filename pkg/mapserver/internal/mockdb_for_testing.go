package internal

import (
	"context"
	"database/sql"
	"time"

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

var _ db.Conn = (*MockDB)(nil)

// newMockDB: return a new mock db
func NewMockDB() *MockDB {
	return &MockDB{
		TreeTable:          make(map[common.SHA256Output][]byte),
		DomainEntriesTable: make(map[common.SHA256Output][]byte),
		UpdatesTable:       make(map[common.SHA256Output]struct{}),
	}
}

func (d *MockDB) DB() *sql.DB {
	return nil
}

// Close closes the connection.
func (d *MockDB) Close() error { return nil }

func (d *MockDB) TruncateAllTables(ctx context.Context) error { return nil }

func (*MockDB) LoadRoot(ctx context.Context) (*common.SHA256Output, error) { return nil, nil }

func (d *MockDB) CheckCertsExist(ctx context.Context, ids []*common.SHA256Output) ([]bool, error) {
	return make([]bool, len(ids)), nil
}

func (d *MockDB) InsertCerts(ctx context.Context, ids, parents []*common.SHA256Output,
	expirations []*time.Time, payloads [][]byte) error {

	return nil
}

func (d *MockDB) UpdateDomainsWithCerts(ctx context.Context, certIDs, domainIDs []*common.SHA256Output,
	domainNames []string) error {

	return nil
}

func (d *MockDB) RetrieveTreeNode(ctx context.Context, id common.SHA256Output) ([]byte, error) {
	return d.TreeTable[id], nil
}

func (d *MockDB) RetrieveDomainEntry(ctx context.Context, key common.SHA256Output) ([]byte, error) {
	return d.DomainEntriesTable[key], nil
}

func (d *MockDB) RetrieveKeyValuePairTreeStruct(ctx context.Context, id []common.SHA256Output,
	numOfRoutine int) ([]*db.KeyValuePair, error) {
	result := []*db.KeyValuePair{}
	for _, key := range id {
		value, ok := d.TreeTable[key]
		if !ok {
			continue
		}
		result = append(result, &db.KeyValuePair{Key: key, Value: value})
	}
	return result, nil
}

func (d *MockDB) RetrieveDomainEntries(ctx context.Context, ids []common.SHA256Output) (
	[]*db.KeyValuePair, error) {

	result := make([]*db.KeyValuePair, 0, len(ids))
	for _, key := range ids {
		value, ok := d.DomainEntriesTable[key]
		if !ok {
			continue
		}
		result = append(result, &db.KeyValuePair{Key: key, Value: value})
	}
	return result, nil
}

func (d *MockDB) RetrieveUpdatedDomains(ctx context.Context, perQueryLimit int) ([]common.SHA256Output, error) {
	result := []common.SHA256Output{}
	for k := range d.UpdatesTable {
		result = append(result, k)
	}
	return result, nil
}

func (d *MockDB) CountUpdatedDomains(ctx context.Context) (int, error) {
	return len(d.UpdatesTable), nil
}

func (d *MockDB) UpdateDomainEntries(ctx context.Context, keyValuePairs []*db.KeyValuePair) (int, error) {
	for _, pair := range keyValuePairs {
		d.DomainEntriesTable[pair.Key] = pair.Value
	}

	return 0, nil
}

func (d *MockDB) UpdateTreeNodes(ctx context.Context, keyValuePairs []*db.KeyValuePair) (int, error) {
	for _, pair := range keyValuePairs {
		d.TreeTable[pair.Key] = pair.Value
	}

	return 0, nil
}

func (d *MockDB) DeleteTreeNodes(ctx context.Context, keys []common.SHA256Output) (int, error) {
	for _, key := range keys {
		delete(d.TreeTable, key)
	}
	return 0, nil
}

func (d *MockDB) AddUpdatedDomains(ctx context.Context, keys []common.SHA256Output) (int, error) {
	for _, key := range keys {
		d.UpdatesTable[key] = empty
	}
	return 0, nil
}

func (d *MockDB) RemoveAllUpdatedDomains(ctx context.Context) error {
	d.UpdatesTable = make(map[common.SHA256Output]struct{})
	return nil
}

func (d *MockDB) UpdatedDomains() (chan []common.SHA256Output, chan error) { return nil, nil }

func (*MockDB) CleanupDirty(ctx context.Context) error { return nil }
