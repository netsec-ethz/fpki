package updater

import (
	"bytes"
	"database/sql"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/logpicker"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
)

// MapUpdater: map updator. It is responsible for updating the tree, and writing to db
type MapUpdater struct {
	smt *trie.Trie
}

// NewMapUpdater: return a new map updator. Input paras is similiar to NewMapResponder
func NewMapUpdater(db db.Conn, root []byte, cacheHeight int, initTable bool) (*MapUpdater, error) {
	smt, err := trie.NewTrie(root, trie.Hasher, db)
	if err != nil {
		return nil, fmt.Errorf("NewMapServer | NewTrie | %w", err)
	}
	smt.CacheHeightLimit = cacheHeight

	logpicker, err := logpicker.NewLogPicker(20, db)
	if err != nil {
		return nil, fmt.Errorf("NewMapServer | NewLogPicker | %w", err)
	}

	return &MapUpdater{smt: smt, logpicker: logpicker}, nil
}

func (mapUpdator *MapUpdater) CollectCertsAndUpdate(ctUrl string, startIdx, endIdx int64) error {
	numOfAffectedDomains, numOfUpdatedCerts, err := mapUpdator.logpicker.UpdateDomainFromLog(ctUrl, startIdx, endIdx, 30, 600)
	if err != nil {
		return fmt.Errorf("CollectCertsAndUpdate | UpdateDomainFromLog | %w", err)
	}
	fmt.Println("number of affected domains: ", numOfAffectedDomains)
	fmt.Println("number of updated certs: ", numOfUpdatedCerts)

	effectedDomains, err := mapUpdator.fetchUpdatedDomainIndex()
	if err != nil {
		return fmt.Errorf("CollectCertsAndUpdate | fetchUpdatedDomainIndex | %w", err)
	}

	if len(effectedDomains) == 0 {
		fmt.Println("nothing to update")
		return nil
	}

	updateInputs, err := mapUpdator.fetchDomainContent(effectedDomains)

	keys := [][]byte{}
	values := [][]byte{}

	for _, v := range updateInputs {
		keys = append(keys, v.Key)
		values = append(values, v.Value)
	}

	_, err = mapUpdator.smt.Update(keys, values)
	if err != nil {
		return fmt.Errorf("CollectCertsAndUpdate | Update | %w", err)
	}

	// commit the changes to db
	err = mapUpdator.smt.Commit()
	if err != nil {
		return fmt.Errorf("CollectCertsAndUpdate | StoreUpdatedNode | %w", err)
	}
	// TODO(yongzhe): remove it later. for debuging onlu
	mapUpdator.smt.PrintCacheSize()

	return nil
}

func (mapUpdator *MapUpdater) fetchDomainContent(domainNames []string) ([]UpdateInput, error) {
	updateInputs := []UpdateInput{}

	var querySB strings.Builder
	querySB.WriteString("SELECT * FROM `map`.`domainEntries` WHERE `key` IN (")

	isFirst := true
	// prepare queries
	for _, key := range domainNames {
		if isFirst {
			querySB.WriteString("'" + key + "'")
			isFirst = false
		} else {
			querySB.WriteString(",'" + key + "'")
		}
	}
	querySB.WriteString(");")

	db, err := sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/map?maxAllowedPacket=1073741824")
	defer db.Close()
	if err != nil {
		return nil, fmt.Errorf("fetchDomainContent | sql.Open | %w", err)
	}

	result, err := db.Query(querySB.String())
	if err != nil {
		return nil, fmt.Errorf("fetchDomainContent | db.Query | %w", err)
	}

	var key string
	var value string
	for result.Next() {
		err := result.Scan(&key, &value)
		if err != nil {
			return nil, fmt.Errorf("fetchDomainContent | Scan | %w", err)
		}
		keyBytes, err := hex.DecodeString(key)
		if err != nil {
			return nil, fmt.Errorf("fetchDomainContent | DecodeString | %w", err)
		}
		updateInputs = append(updateInputs, UpdateInput{Key: keyBytes, Value: trie.Hasher([]byte(value))})
	}

	sort.Slice(updateInputs, func(i, j int) bool {
		return bytes.Compare(updateInputs[i].Key, updateInputs[j].Key) == -1
	})

	return updateInputs, nil
}

func (mapUpdator *MapUpdater) fetchUpdatedDomainIndex() ([]string, error) {
	db, err := sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/map?maxAllowedPacket=1073741824")
	defer db.Close()
	if err != nil {
		return nil, fmt.Errorf("fetchUpdatedDomainIndex | sql.Open | %w", err)
	}

	result, err := db.Query("SELECT * FROM `map`.`updatedDomains`;")
	if err != nil {
		return nil, fmt.Errorf("fetchUpdatedDomainIndex | db.Query | %w", err)
	}
	defer result.Close()

	domainList := []string{}
	var newDomainName string
	for result.Next() {
		err := result.Scan(&newDomainName)
		if err != nil {
			return nil, fmt.Errorf("fetchUpdatedDomainIndex | Scan | %w", err)
		}
		domainList = append(domainList, newDomainName)
	}

	// clear the table
	_, err = db.Exec("TRUNCATE `map`.`updatedDomains`;")
	if err != nil {
		return nil, fmt.Errorf("fetchUpdatedDomainIndex | db.Exec TRANCATE | %w", err)
	}

	return domainList, nil
}

// GetRoot: get current root
func (mapUpdater *MapUpdater) GetRoot() []byte {
	return mapUpdater.smt.Root
}

// Close: close connection
func (mapUpdater *MapUpdater) Close() error {
	return mapUpdater.smt.Close()
}
