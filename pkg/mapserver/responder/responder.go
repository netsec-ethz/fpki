package responder

import (
	"context"
	"fmt"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	mapCommon "github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/domain"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
)

type responderWorker struct {
	dbConn          db.Conn
	smt             *trie.Trie
	clientInputChan chan ClientRequest
}

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

func NewMapResponder(root []byte, cacheHeight int, workerThreadNum int) (*MapResponder, error) {
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
		dbConn, err := db.Connect(&config)
		if err != nil {
			return nil, fmt.Errorf("NewUpdatedMapResponder | Connect | %w", err)
		}
		newWorker := &responderWorker{dbConn: dbConn, clientInputChan: clientInputChan, smt: smt}
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
	result := <-resultChan
	return result.Proof, result.Err
}

/*
func worker(workerChan chan ClientRequest) {
	for {
		request := <-workerChan

	}
}*/

func (responderWorker *responderWorker) work() {
	for {
		newRequest := <-responderWorker.clientInputChan

		proofs, err := responderWorker.getDomainProof(newRequest.ctx, newRequest.domainName)
		if err != nil {
			newRequest.resultChan <- ClientResponse{Err: err}
		}
		newRequest.resultChan <- ClientResponse{Proof: proofs}
	}
}

func (responderWorker *responderWorker) getDomainProof(ctx context.Context, domainName string) ([]mapCommon.MapServerResponse, error) {
	//start := time.Now()
	proofsResult := []mapCommon.MapServerResponse{}
	domainList, err := parseDomainName(domainName)
	if err != nil {
		return nil, fmt.Errorf("GetDomainProof | parseDomainName | %w", err)
	}

	// var for benchmark
	// TODO(yongzhe): delete this later
	/*
		var merStart time.Time
		var merEnd time.Time
		var newStart time.Time
		var newEnd time.Time
		var hashStart time.Time
		var hashEnd time.Time
		var dbReadTime []time.Duration
		var resultSize []int
	*/

	//durationList := []time.Duration{}

	for _, domain := range domainList {
		// hash the domain name -> key
		//hashStart = time.Now()
		domainHash := common.SHA256Hash32Bytes([]byte(domain))
		//hashEnd = time.Now()
		//durationList = append(durationList, hashEnd.Sub(hashStart))

		// get the merkle proof from the smt. If isPoP == true, then it's a proof of inclusion
		//merStart = time.Now()
		proof, isPoP, proofKey, ProofValue, err := responderWorker.smt.MerkleProof(domainHash[:])
		if err != nil {
			return nil, fmt.Errorf("GetProofs | MerkleProof | %w", err)
		}
		//merEnd = time.Now()
		//if merEnd.Sub(merStart) > time.Millisecond {
		//	fmt.Println("fetch proof: ", merEnd.Sub(merStart))
		//}

		//durationList = append(durationList, merEnd.Sub(merStart))

		//newStart = time.Now()
		var proofType mapCommon.ProofType
		domainBytes := []byte{}
		// If it is PoP, query the domain entry. If it is PoA, directly return the PoA
		switch {
		case isPoP:
			proofType = mapCommon.PoP
			//dbStart := time.Now()
			result, err := responderWorker.dbConn.RetrieveOneKeyValuePairDomainEntries(ctx, domainHash)
			if err != nil {
				return nil, fmt.Errorf("GetDomainProof | QueryRow | %w", err)
			}
			//dbEnd := time.Now()
			//dbReadTime = append(dbReadTime, dbEnd.Sub(dbStart))
			//resultSize = append(resultSize, len(result.Value))
			domainBytes = result.Value

		case !isPoP:
			proofType = mapCommon.PoA
		}
		//newEnd = time.Now()

		//durationList = append(durationList, newEnd.Sub(newStart))

		proofsResult = append(proofsResult, mapCommon.MapServerResponse{
			Domain: domain,
			PoI: mapCommon.PoI{
				Proof:      proof,
				Root:       responderWorker.smt.Root,
				ProofType:  proofType,
				ProofKey:   proofKey,
				ProofValue: ProofValue},
			DomainEntryBytes: domainBytes,
		})
	}
	//end := time.Now()
	// print the slow query
	/*
		if end.Sub(start) > time.Millisecond {
			fmt.Println("time to fetch: ", end.Sub(start))
			fmt.Println(domainName)
			for i, timeST := range durationList {
				fmt.Println(timeST)
				if i%3 == 2 {
					fmt.Println()
				}
			}
			fmt.Println("db read time")
			for _, dbTime := range dbReadTime {
				fmt.Println(dbTime)
			}

			for _, domain := range domainList {
				fmt.Println("key", hex.EncodeToString(trie.Hasher([]byte(domain))))
			}

			for _, resultSize := range resultSize {
				fmt.Println("size: ", resultSize)
			}

			fmt.Println("--------------------------------------")
		}
	*/

	return proofsResult, nil
}

// parseDomainName: get the parent domain until E2LD, return a list of domains(remove the www. and *.)
// eg: video.google.com -> video.google.com google.com
// eg: *.google.com -> google.com
// eg: www.google.com -> google.com
func parseDomainName(domainName string) ([]string, error) {
	result, err := domain.SplitE2LD(domainName)
	resultString := []string{}
	var domain string
	if err != nil {
		return nil, fmt.Errorf("parseDomainName | SplitE2LD | %w", err)
	} else if len(result) == 0 {
		return nil, fmt.Errorf("domain length is zero")
	}
	domain = result[len(result)-1]
	resultString = append(resultString, domain)
	for i := len(result) - 2; i >= 0; i-- {
		domain = result[i] + "." + domain
		resultString = append(resultString, domain)
	}
	return resultString, nil
}

// GetRoot: get current root of the smt
func (mapResponder *MapResponder) GetRoot() []byte {
	return mapResponder.smt.Root
}

// Close: close db
func (mapResponder *MapResponder) Close() error {
	return mapResponder.smt.Close()
}
