package responder

import (
	"context"
	"fmt"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	mapCommon "github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
)

// ClientRequest: client's request
type ClientRequest struct {
	domainName string
	ctx        context.Context
	resultChan chan ClientResponse
}

// ClientResponse: response to client's request
type ClientResponse struct {
	Proof []mapCommon.MapServerResponse
	Err   error
}

// MapResponder: A map responder, which is responsible for receiving client's request. Only read from db.
type MapResponder struct {
	workerPool []*responderWorker
	workerChan chan ClientRequest
	smt        *trie.Trie
	tempStore  *TempStore
}

// NewMapResponder: return a new responder
func NewMapResponder(ctx context.Context, root []byte, cacheHeight int, workerThreadNum int) (*MapResponder, error) {
	config := db.Configuration{
		Dsn: "root@tcp(localhost)/fpki",
		Values: map[string]string{
			"interpolateParams": "true", // 1 round trip per query
			"collation":         "binary",
		},
	}

	// new db connection for SMT
	dbConn, err := db.Connect(&config)
	if err != nil {
		return nil, fmt.Errorf("NewMapResponder | Connect | %w", err)
	}

	smt, err := trie.NewTrie(root, common.SHA256Hash, dbConn)
	if err != nil {
		return nil, fmt.Errorf("NewMapResponder | NewTrie | %w", err)
	}
	smt.CacheHeightLimit = cacheHeight

	// load cache
	err = smt.LoadCache(ctx, root)
	if err != nil {
		return nil, fmt.Errorf("NewMapResponder | LoadCache | %w", err)
	}

	clientInputChan := make(chan ClientRequest)
	workerPool := make([]*responderWorker, 0, workerThreadNum)

	// create worker pool
	for i := 0; i < workerThreadNum; i++ {
		newDbConn, err := db.Connect(&config)
		if err != nil {
			return nil, fmt.Errorf("NewUpdatedMapResponder | Connect | %w", err)
		}
		newWorker := &responderWorker{
			dbConn:          newDbConn,
			clientInputChan: clientInputChan,
			smt:             smt,
		}
		workerPool = append(workerPool, newWorker)
		go newWorker.work()
	}

	tempStore := newTempStore()

	return &MapResponder{
		workerChan: clientInputChan,
		workerPool: workerPool,
		smt:        smt,
		tempStore:  tempStore,
	}, nil
}

// GetProof: get proofs for one domain
func (responder *MapResponder) GetProof(ctx context.Context, domainName string) ([]mapCommon.MapServerResponse, error) {
	resultChan := make(chan ClientResponse)

	responder.workerChan <- ClientRequest{domainName: domainName, ctx: ctx, resultChan: resultChan}
	result := <-resultChan
	close(resultChan)

	return result.Proof, result.Err
}

// GetRoot: get current root of the smt
func (mapResponder *MapResponder) GetRoot() []byte {
	return mapResponder.smt.Root
}

// Close: close db
func (mapResponder *MapResponder) Close() error {
	for _, worker := range mapResponder.workerPool {
		close(worker.clientInputChan)
		err := worker.dbConn.Close()
		if err != nil {
			return fmt.Errorf("Close | %w", err)
		}
	}
	return mapResponder.smt.Close()
}
