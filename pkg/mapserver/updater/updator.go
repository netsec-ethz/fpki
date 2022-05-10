package updater

import (
	"database/sql"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
	"github.com/netsec-ethz/fpki/pkg/mapserver/common"
	tire "github.com/netsec-ethz/fpki/pkg/mapserver/tire"
)

type MapUpdater struct {
	smt *tire.Trie
}

func NewMapUpdater(db *sql.DB, root []byte, cacheHeight int) (*MapUpdater, error) {
	smt, err := tire.NewTrie(root, tire.Hasher, *db)
	if err != nil {
		return nil, fmt.Errorf("NewMapServer | NewTrie | %w", err)
	}
	smt.CacheHeightLimit = cacheHeight
	if err != nil {
		return nil, fmt.Errorf("NewMapServer | NewSMT | %w", err)
	}

	return &MapUpdater{smt: smt}, nil
}

func (mapUpdater *MapUpdater) UpdateDomains(domainEntries []common.DomainEntry) error {
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

	err = mapUpdater.smt.Commit()
	if err != nil {
		return fmt.Errorf("UpdateDomains | StoreUpdatedNode | %w", err)
	}
	mapUpdater.smt.PrintCacheSize()
	return nil
}

func (mapUpdater *MapUpdater) GetRoot() []byte {
	return mapUpdater.smt.Root
}

func (mapUpdater *MapUpdater) Close() error {
	return mapUpdater.smt.Close()
}
