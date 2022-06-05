package updater

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/domain"
	"github.com/netsec-ethz/fpki/pkg/mapserver/logpicker"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
)

// MapUpdater: map updater. It is responsible for updating the tree, and writing to db
type MapUpdater struct {
	smt          *trie.Trie
	dbConn       db.Conn
	domainParser *domain.DomainParser
}

// NewMapUpdater: return a new map updater. Input paras is similar to NewMapResponder
func NewMapUpdater(root []byte, cacheHeight int) (*MapUpdater, error) {
	parser, err := domain.NewDomainParser()
	if err != nil {
		return nil, fmt.Errorf("NewMapUpdater | NewDomainParser | %w", err)
	}

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

	smt, err := trie.NewTrie(root, common.SHA256Hash, dbConn)
	if err != nil {
		return nil, fmt.Errorf("NewMapServer | NewTrie | %w", err)
	}
	smt.CacheHeightLimit = cacheHeight

	return &MapUpdater{smt: smt, dbConn: dbConn, domainParser: parser}, nil
}

// UpdateFromCT: download certs from ct log, update the domain entries and update the updates table, and SMT;
// SMT not committed yet
func (mapUpdater *MapUpdater) UpdateFromCT(ctx context.Context, ctUrl string, startIdx, endIdx int64) error {
	fmt.Println("****** UpdateFromCT ******")
	start := time.Now()
	fmt.Println(startIdx, endIdx)
	certs, err := logpicker.GetCertMultiThread(ctUrl, startIdx, endIdx, 20)
	if err != nil {
		return fmt.Errorf("CollectCerts | GetCertMultiThread | %w", err)
	}
	end := time.Now()
	fmt.Println("time to fetch certs from internet         ", end.Sub(start), " ", len(certs))

	//start = time.Now()

	//fmt.Println(" ------UpdateDomainEntriesUsingCerts -----")
	_, err = mapUpdater.UpdateDomainEntriesUsingCerts(ctx, certs, 10)
	if err != nil {
		return fmt.Errorf("CollectCerts | UpdateDomainEntriesUsingCerts | %w", err)
	}
	//end = time.Now()
	//fmt.Println("time to UpdateDomainEntriesUsingCerts     ", end.Sub(start))

	//start = time.Now()
	updatedDomainHash, err := mapUpdater.fetchUpdatedDomainHash(ctx)
	if err != nil {
		return fmt.Errorf("CollectCerts | fetchUpdatedDomainHash | %w", err)
	}
	//end = time.Now()
	//fmt.Println("time to fetchUpdatedDomainHash            ", end.Sub(start))

	//start = time.Now()
	keyValuePairs, err := mapUpdater.dbConn.RetrieveKeyValuePairDomainEntries(ctx, updatedDomainHash, 10)
	if err != nil {
		return fmt.Errorf("CollectCerts | RetrieveKeyValuePairMultiThread | %w", err)
	}

	//end = time.Now()
	//fmt.Println("time to RetrieveKeyValuePairMultiThread   ", end.Sub(start))

	//start = time.Now()
	keyInput, valueInput, err := keyValuePairToSMTInput(keyValuePairs)
	if err != nil {
		return fmt.Errorf("CollectCerts | keyValuePairToSMTInput | %w", err)
	}
	//end = time.Now()
	//fmt.Println("time to keyValuePairToSMTInput            ", end.Sub(start))

	//start = time.Now()
	_, err = mapUpdater.smt.Update(ctx, keyInput, valueInput)
	if err != nil {
		return fmt.Errorf("CollectCerts | Update | %w", err)
	}
	//end = time.Now()
	//fmt.Println("time to Update SMT                        ", end.Sub(start))
	//fmt.Println("****** UpdateFromCT End ******")

	return nil
}

// UpdateRPCAndPC: update RPC and PC from url. Currently just download
func (mapUpdater *MapUpdater) UpdateRPCAndPC(ctx context.Context, ctUrl string, startIdx, endIdx int64) error {
	// get PC and RPC first
	pcList, rpcList, err := logpicker.GetPCAndRPC(ctUrl, startIdx, endIdx, 20)
	if err != nil {
		return fmt.Errorf("CollectCerts | GetPCAndRPC | %w", err)
	}

	// update the domain and
	_, err = mapUpdater.UpdateDomainEntriesUsingRPCAndPC(ctx, rpcList, pcList, 10)
	if err != nil {
		return fmt.Errorf("CollectCerts | UpdateDomainEntriesUsingRPCAndPC | %w", err)
	}

	updatedDomainHash, err := mapUpdater.fetchUpdatedDomainHash(ctx)
	if err != nil {
		return fmt.Errorf("CollectCerts | fetchUpdatedDomainHash | %w", err)
	}

	// fetch domains from DB
	keyValuePairs, err := mapUpdater.dbConn.RetrieveKeyValuePairDomainEntries(ctx, updatedDomainHash, 10)
	if err != nil {
		return fmt.Errorf("CollectCerts | RetrieveKeyValuePairMultiThread | %w", err)
	}

	keyInput, valueInput, err := keyValuePairToSMTInput(keyValuePairs)
	if err != nil {
		return fmt.Errorf("CollectCerts | keyValuePairToSMTInput | %w", err)
	}

	// update Sparse Merkle Tree
	_, err = mapUpdater.smt.Update(ctx, keyInput, valueInput)
	if err != nil {
		return fmt.Errorf("CollectCerts | Update | %w", err)
	}

	return nil
}

// CommitChanges: commit changes to DB
func (mapUpdater *MapUpdater) CommitChanges(ctx context.Context) error {
	err := mapUpdater.smt.Commit(ctx)
	if err != nil {
		return fmt.Errorf("CommitChanges | Commit | %w", err)
	}
	return nil
}

func (mapUpdater *MapUpdater) fetchUpdatedDomainHash(ctx context.Context) ([]common.SHA256Output, error) {
	keys, err := mapUpdater.dbConn.RetrieveUpdatedDomainHashesUpdates(ctx, readBatchSize)
	if err != nil {
		return nil, fmt.Errorf("fetchUpdatedDomainHash | RetrieveUpdatedDomainMultiThread | %w", err)
	}

	err = mapUpdater.dbConn.TruncateUpdatesTableUpdates(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetchUpdatedDomainHash | TruncateUpdatesTableUpdates | %w", err)
	}

	return keys, nil
}

func keyValuePairToSMTInput(keyValuePair []db.KeyValuePair) ([][]byte, [][]byte, error) {

	updateInput := []UpdateInput{}

	for _, pair := range keyValuePair {
		updateInput = append(updateInput, UpdateInput{Key: pair.Key, Value: common.SHA256Hash(pair.Value)})
	}

	sort.Slice(updateInput, func(i, j int) bool {
		return bytes.Compare(updateInput[i].Key[:], updateInput[j].Key[:]) == -1
	})

	keyResult := [][]byte{}
	valueResult := [][]byte{}

	for _, pair := range updateInput {
		// TODO(yongzhe): strange error
		// if I do : append(keyResult, pair.Key[:]), the other elements in the slice will be affected
		// Looks like the slice is storing the pointer of the value.
		// However, append(valueResult, pair.Value) also works. I will have a look later
		var newKey [32]byte
		copy(newKey[:], pair.Key[:])
		keyResult = append(keyResult, newKey[:])

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
