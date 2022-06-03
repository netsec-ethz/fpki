package updater

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/logpicker"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
)

// MapUpdater: map updator. It is responsible for updating the tree, and writing to db
type MapUpdater struct {
	smt    *trie.Trie
	dbConn db.Conn
}

// NewMapUpdater: return a new map updator. Input paras is similiar to NewMapResponder
func NewMapUpdater(root []byte, cacheHeight int) (*MapUpdater, error) {
	config := db.Configuration{
		Dsn: "root@tcp(localhost)/fpki",
		Values: map[string]string{
			"interpolateParams": "true", // 1 round trip per query
			"collation":         "binary",
		},
	}

	dbConn, err := db.Connect(&config)
	if err != nil {
		return nil, fmt.Errorf("NewMapUpdater | db.Connect | %w", err)
	}

	smt, err := trie.NewTrie(root, trie.Hasher, dbConn)
	if err != nil {
		return nil, fmt.Errorf("NewMapServer | NewTrie | %w", err)
	}
	smt.CacheHeightLimit = cacheHeight

	return &MapUpdater{smt: smt, dbConn: dbConn}, nil
}

// UpdateFromCT: download certs from ct log, update the domain entries and update the updates table, and SMT;
// SMT not committed yet
func (mapUpdator *MapUpdater) UpdateFromCT(ctUrl string, startIdx, endIdx int64) error {
	fmt.Println("****** UpdateFromCT ******")
	start := time.Now()
	fmt.Println(startIdx, endIdx)
	certs, err := logpicker.GetCertMultiThread(ctUrl, startIdx, endIdx, 20)
	if err != nil {
		return fmt.Errorf("CollectCerts | GetCertMultiThread | %w", err)
	}
	end := time.Now()
	fmt.Println("time to fetch certs from internet         ", end.Sub(start), " ", len(certs))

	start = time.Now()
	fmt.Println()
	fmt.Println(" ------UpdateDomainEntriesUsingCerts -----")
	_, err = mapUpdator.UpdateDomainEntriesUsingCerts(certs, 10)
	if err != nil {
		return fmt.Errorf("CollectCerts | UpdateDomainEntriesUsingCerts | %w", err)
	}
	end = time.Now()
	fmt.Println("time to UpdateDomainEntriesUsingCerts     ", end.Sub(start))
	fmt.Println()

	start = time.Now()
	updatedDomainHash, err := mapUpdator.fetchUpdatedDomainHash()
	if err != nil {
		return fmt.Errorf("CollectCerts | fetchUpdatedDomainHash | %w", err)
	}
	end = time.Now()
	fmt.Println("time to fetchUpdatedDomainHash            ", end.Sub(start))

	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	start = time.Now()
	keyValuePairs, err := mapUpdator.dbConn.RetrieveKeyValuePair_DomainEntries(ctx, updatedDomainHash, 10)
	if err != nil {
		return fmt.Errorf("CollectCerts | RetrieveKeyValuePairMultiThread | %w", err)
	}
	end = time.Now()
	fmt.Println("time to RetrieveKeyValuePairMultiThread   ", end.Sub(start))

	start = time.Now()
	keyInput, valueInput, err := keyValuePairToSMTInput(keyValuePairs)
	if err != nil {
		return fmt.Errorf("CollectCerts | keyValuePairToSMTInput | %w", err)
	}
	end = time.Now()
	fmt.Println("time to keyValuePairToSMTInput            ", end.Sub(start))

	start = time.Now()
	_, err = mapUpdator.smt.Update(keyInput, valueInput)
	if err != nil {
		return fmt.Errorf("CollectCerts | Update | %w", err)
	}
	end = time.Now()
	fmt.Println("time to Update SMT                        ", end.Sub(start))
	fmt.Println("****** UpdateFromCT End ******")

	return nil
}

// UpdateRPCAndPC: update RPC and PC from url. Currently just download
func (mapUpdator *MapUpdater) UpdateRPCAndPC(ctUrl string, startIdx, endIdx int64) error {
	// get PC and RPC first
	pcList, rpcList, err := logpicker.GetPCAndRPC(ctUrl, startIdx, endIdx, 20)
	if err != nil {
		return fmt.Errorf("CollectCerts | GetPCAndRPC | %w", err)
	}

	// update the domain and
	_, err = mapUpdator.UpdateDomainEntriesUsingRPCAndPC(rpcList, pcList, 10)
	if err != nil {
		return fmt.Errorf("CollectCerts | UpdateDomainEntriesUsingRPCAndPC | %w", err)
	}

	updatedDomainHash, err := mapUpdator.fetchUpdatedDomainHash()
	if err != nil {
		return fmt.Errorf("CollectCerts | fetchUpdatedDomainHash | %w", err)
	}

	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	// fetch domains from DB
	keyValuePairs, err := mapUpdator.dbConn.RetrieveKeyValuePair_DomainEntries(ctx, updatedDomainHash, 10)
	if err != nil {
		return fmt.Errorf("CollectCerts | RetrieveKeyValuePairMultiThread | %w", err)
	}

	keyInput, valueInput, err := keyValuePairToSMTInput(keyValuePairs)
	if err != nil {
		return fmt.Errorf("CollectCerts | keyValuePairToSMTInput | %w", err)
	}

	// update Sparse Merkle Tree
	_, err = mapUpdator.smt.Update(keyInput, valueInput)
	if err != nil {
		return fmt.Errorf("CollectCerts | Update | %w", err)
	}

	return nil
}

// CommitChanges: commit changes to DB
func (mapUpdator *MapUpdater) CommitChanges() error {
	err := mapUpdator.smt.Commit()
	if err != nil {
		return fmt.Errorf("CommitChanges | Commit | %w", err)
	}
	return nil
}

func (mapUpdator *MapUpdater) fetchUpdatedDomainHash() ([]string, error) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	keys, err := mapUpdator.dbConn.RetrieveUpdatedDomainHashes_Updates(ctx, readBatchSize)
	if err != nil {
		return nil, fmt.Errorf("fetchUpdatedDomainHash | RetrieveUpdatedDomainMultiThread | %w", err)
	}
	return keys, nil
}

func keyValuePairToSMTInput(keyValuePair []db.KeyValuePair) ([][]byte, [][]byte, error) {
	updateInput := []UpdateInput{}

	for _, pair := range keyValuePair {
		keyBytes, err := hex.DecodeString(pair.Key)
		if err != nil {
			return nil, nil, fmt.Errorf("keyValuePairToSMTInput | DecodeString | %w", err)
		}
		updateInput = append(updateInput, UpdateInput{Key: keyBytes, Value: trie.Hasher(pair.Value)})
	}

	sort.Slice(updateInput, func(i, j int) bool {
		return bytes.Compare(updateInput[i].Key, updateInput[j].Key) == -1
	})

	keyResult := [][]byte{}
	valueResult := [][]byte{}

	for _, pair := range updateInput {
		keyResult = append(keyResult, pair.Key)
		valueResult = append(valueResult, pair.Value)
	}

	return keyResult, valueResult, nil
}

// GetRoot: get current root
func (mapUpdater *MapUpdater) GetRoot() []byte {
	return mapUpdater.smt.Root
}

// Close: close connection
func (mapUpdater *MapUpdater) Close() error {
	return mapUpdater.smt.Close()
}

/*
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
*/
