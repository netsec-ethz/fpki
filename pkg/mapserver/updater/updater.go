package updater

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"time"

	_ "github.com/go-sql-driver/mysql"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/logpicker"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
)

// MapUpdater: map updater. It is responsible for updating the tree, and writing to db
type MapUpdater struct {
	Fetcher logpicker.LogFetcher
	smt     *trie.Trie
	dbConn  db.Conn
}

// NewMapUpdater: return a new map updater.
func NewMapUpdater(root []byte, cacheHeight int) (*MapUpdater, error) {
	// db conn for map updater
	dbConn, err := db.Connect(nil)
	if err != nil {
		return nil, fmt.Errorf("NewMapUpdater | db.Connect | %w", err)
	}

	// SMT
	smt, err := trie.NewTrie(root, common.SHA256Hash, dbConn)
	if err != nil {
		return nil, fmt.Errorf("NewMapServer | NewTrie | %w", err)
	}
	smt.CacheHeightLimit = cacheHeight

	return &MapUpdater{
		Fetcher: logpicker.LogFetcher{
			WorkerCount: 32,
		},
		smt:    smt,
		dbConn: dbConn,
	}, nil
}

// StartFetching will initiate the CT logs fetching process in the background, trying to
// obtain the next batch of certificates and have it ready for the next update.
func (u *MapUpdater) StartFetching(ctURL string, startIndex, endIndex int) {
	u.Fetcher.URL = ctURL
	u.Fetcher.Start = startIndex
	u.Fetcher.End = endIndex
	u.Fetcher.StartFetching()
}

// UpdateNextBatch downloads the next batch from the CT log server and updates the domain and
// Updates tables. Also the SMT.
func (u *MapUpdater) UpdateNextBatch(ctx context.Context) (int, error) {
	certs, err := u.Fetcher.NextBatch(ctx)
	if err != nil {
		return 0, fmt.Errorf("CollectCerts | GetCertMultiThread | %w", err)
	}
	return len(certs), u.updateCerts(ctx, certs)
}

// updateCerts: update the tables and SMT (in memory) using certificates
func (mapUpdater *MapUpdater) updateCerts(ctx context.Context, certs []*ctx509.Certificate) error {
	start := time.Now()
	keyValuePairs, numOfUpdates, err := mapUpdater.UpdateDomainEntriesTableUsingCerts(ctx, certs, 10)
	if err != nil {
		return fmt.Errorf("CollectCerts | UpdateDomainEntriesUsingCerts | %w", err)
	} else if numOfUpdates == 0 {
		return nil
	}

	end := time.Now()
	fmt.Println("(db and memory) time to update domain entries: ", end.Sub(start))

	if len(keyValuePairs) == 0 {
		return nil
	}

	keyInput, valueInput, err := keyValuePairToSMTInput(keyValuePairs)
	if err != nil {
		return fmt.Errorf("CollectCerts | keyValuePairToSMTInput | %w", err)
	}

	start = time.Now()
	_, err = mapUpdater.smt.Update(ctx, keyInput, valueInput)
	if err != nil {
		return fmt.Errorf("CollectCerts | Update | %w", err)
	}
	end = time.Now()
	fmt.Println("(memory) time to update tree in memory: ", end.Sub(start))

	return nil
}

// UpdateRPCAndPC: update RPC and PC from url. Currently just mock PC and RPC
func (mapUpdater *MapUpdater) UpdateRPCAndPC(ctx context.Context, ctUrl string, startIdx, endIdx int64) error {
	// get PC and RPC first
	pcList, rpcList, err := logpicker.GetPCAndRPC(ctUrl, startIdx, endIdx, 20)
	if err != nil {
		return fmt.Errorf("CollectCerts | GetPCAndRPC | %w", err)
	}
	return mapUpdater.updateRPCAndPC(ctx, pcList, rpcList)
}

// updateRPCAndPC: update the tables and SMT (in memory) using PC and RPC
func (mapUpdater *MapUpdater) updateRPCAndPC(ctx context.Context, pcList []*common.PC, rpcList []*common.RPC) error {
	// update the domain and
	keyValuePairs, _, err := mapUpdater.UpdateDomainEntriesTableUsingRPCAndPC(ctx, rpcList, pcList, 10)
	if err != nil {
		return fmt.Errorf("CollectCerts | UpdateDomainEntriesUsingRPCAndPC | %w", err)
	}

	if len(keyValuePairs) == 0 {
		return nil
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

// CommitSMTChanges: commit SMT changes to DB
func (mapUpdater *MapUpdater) CommitSMTChanges(ctx context.Context) error {
	err := mapUpdater.smt.Commit(ctx)
	if err != nil {
		return fmt.Errorf("CommitChanges | Commit | %w", err)
	}
	return nil
}

// fetchUpdatedDomainHash: get hashes of updated domain from updates table, and truncate the table
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

// keyValuePairToSMTInput: key value pair -> SMT update input
func keyValuePairToSMTInput(keyValuePair []db.KeyValuePair) ([][]byte, [][]byte, error) {
	updateInput := make([]UpdateInput, 0, len(keyValuePair))

	for _, pair := range keyValuePair {
		updateInput = append(updateInput, UpdateInput{Key: pair.Key, Value: common.SHA256Hash(pair.Value)})
	}

	sort.Slice(updateInput, func(i, j int) bool {
		return bytes.Compare(updateInput[i].Key[:], updateInput[j].Key[:]) == -1
	})

	keyResult := make([][]byte, 0, len(updateInput))
	valueResult := make([][]byte, 0, len(updateInput))

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
