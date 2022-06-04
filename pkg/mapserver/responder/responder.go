package responder

import (
	"context"
	"fmt"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/domain"
	mapCommon "github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
)

type ClientRequest struct {
	domainName string
	ctx        context.Context
	resultChan chan ClientResponse
}

type ClientResponse struct {
	Proof []mapCommon.MapServerResponse
	Err   error
}

// NewMapResponder: A map responder, which is responsible for receiving client's request. Only read from db.
type MapResponder struct {
	workerPool []*responderWorker
	workerChan chan ClientRequest
	smt        *trie.Trie
}

// NewMapResponder: return a new responder
func NewMapResponder(root []byte, cacheHeight int, workerThreadNum int) (*MapResponder, error) {
	parser, err := domain.NewDomainParser()
	if err != nil {
		return nil, fmt.Errorf("NewMapResponder | NewDomainParser | %w", err)
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
		return nil, fmt.Errorf("NewMapResponder | Connect | %w", err)
	}

	smt, err := trie.NewTrie(root, common.SHA256Hash, dbConn)
	if err != nil {
		return nil, fmt.Errorf("NewMapResponder | NewTrie | %w", err)
	}
	smt.CacheHeightLimit = cacheHeight
	err = smt.LoadCache(root)
	if err != nil {
		return nil, fmt.Errorf("NewMapResponder | LoadCache | %w", err)
	}

	clientInputChan := make(chan ClientRequest)
	workerPool := []*responderWorker{}

	for i := 0; i < workerThreadNum; i++ {
		newDbConn, err := db.Connect(&config)
		if err != nil {
			return nil, fmt.Errorf("NewUpdatedMapResponder | Connect | %w", err)
		}
		newWorker := &responderWorker{dbConn: newDbConn, clientInputChan: clientInputChan, smt: smt, domainParser: parser}
		workerPool = append(workerPool, newWorker)
		go newWorker.work()
	}

	return &MapResponder{
		workerChan: clientInputChan,
		workerPool: workerPool,
		smt:        smt,
	}, nil
}

func (responder *MapResponder) GetProof(ctx context.Context, domainName string) ([]mapCommon.MapServerResponse, error) {
	resultChan := make(chan ClientResponse)

	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	responder.workerChan <- ClientRequest{domainName: domainName, ctx: ctx, resultChan: resultChan}
	fmt.Println("waiting for response ", domainName)
	result := <-resultChan
	fmt.Println("get response ", domainName)
	close(resultChan)
	return result.Proof, result.Err
}

// GetRoot: get current root of the smt
func (mapResponder *MapResponder) GetRoot() []byte {
	return mapResponder.smt.Root
}

// Close: close db
func (mapResponder *MapResponder) Close() error {
	return mapResponder.smt.Close()
}
