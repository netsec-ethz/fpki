package updater

import (
	"database/sql"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
	"github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
)

// MapUpdater: map updator. It is responsible for updating the tree, and writing to db
type MapUpdater struct {
	smt *trie.Trie
}

// NewMapUpdater: return a new map updator. Input paras is similiar to NewMapResponder
func NewMapUpdater(db *sql.DB, root []byte, cacheHeight int) (*MapUpdater, error) {
	smt, err := trie.NewTrie(root, trie.Hasher, *db, "cacheStore")
	if err != nil {
		return nil, fmt.Errorf("NewMapServer | NewTrie | %w", err)
	}
	smt.CacheHeightLimit = cacheHeight

	return &MapUpdater{smt: smt}, nil
}

// UpdateDomains: update a list of domain entries
func (mapUpdater *MapUpdater) UpdateDomains(domainEntries []common.DomainEntry) error {
	// get key-value pairs ([32]byte - [32]byte) pair
	keyValuePair, err := HashDomainEntriesThenSort(domainEntries)
	if err != nil {
		return fmt.Errorf("UpdateDomains | HashDomainEntriesThenSort | %w", err)
	}

	keys := [][]byte{}
	values := [][]byte{}

	for _, v := range keyValuePair {
		keys = append(keys, v.Key)
		values = append(values, v.Value)
	}

	_, err = mapUpdater.smt.Update(keys, values)
	if err != nil {
		return fmt.Errorf("UpdateDomains | Update | %w", err)
	}

	// commit the changes to db
	err = mapUpdater.smt.Commit()
	if err != nil {
		return fmt.Errorf("UpdateDomains | StoreUpdatedNode | %w", err)
	}
	// TODO(yongzhe): remove it later. for debuging onlu
	mapUpdater.smt.PrintCacheSize()
	return nil
}

// GetRoot: get current root
func (mapUpdater *MapUpdater) GetRoot() []byte {
	return mapUpdater.smt.Root
}

// Close: close connection
func (mapUpdater *MapUpdater) Close() error {
	return mapUpdater.smt.Close()
}
