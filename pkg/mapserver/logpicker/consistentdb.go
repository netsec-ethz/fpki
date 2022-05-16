package logpicker

import (
	"errors"
	"fmt"
	"sync"

	_ "github.com/go-sql-driver/mysql"
)

var tableName = "domainEntries"

var ErrorResourceLocked = errors.New("resource locked")

// RequestType: type of the log picker's request
type RequestType int

const (
	QueryDomain  RequestType = iota
	UpdateDomain RequestType = iota
)

// RequestType: Request from log picker to consistent db
type UpdateRequest struct {
	RequestType          RequestType
	Domains              [][32]byte
	UpdatedDomainName    []string
	UpdatedDomainContent []string
	ReturnChan           chan UpdateResult
}

// UpdateResult: Result from consistent db to log picker
type UpdateResult struct {
	FetchedDomainsName    [][32]byte
	FetchedDomainsContent [][]byte
	Err                   error
}

// ConsistentDB: A db which garentees: one domain can only be accessed by one thread, even it's not existed before
type ConsistentDB struct {
	workerPool            []*dbWorker
	inputChan             chan UpdateRequest
	workerChan            chan UpdateRequest
	processingDomains     map[[32]byte]byte
	processingDomainsLock sync.Mutex
}

// NewConsistentDB: return a new consistent DB
func NewConsistentDB(numOfWorker int, inputChan chan UpdateRequest) (*ConsistentDB, error) {
	db := &ConsistentDB{}
	workerPool := []*dbWorker{}
	workerChan := make(chan UpdateRequest)
	for i := 0; i < numOfWorker; i++ {
		worker, err := newWorker(workerChan, db)
		if err != nil {
			return nil, fmt.Errorf("NewCertProcessor | newWorker | %w", err)
		}
		workerPool = append(workerPool, worker)
	}

	db.workerPool = workerPool
	db.inputChan = inputChan
	db.processingDomains = make(map[[32]byte]byte)
	db.workerChan = workerChan
	return db, nil
}

// StartWork: start working. Blocking function. Use go StartWork() to avoid blocking
func (processor *ConsistentDB) StartWork() {
	for _, worker := range processor.workerPool {
		go worker.work()
	}
	for {
		newRequest := <-processor.inputChan
		switch {
		// if one log picker thread wants to query the effected domains
		case newRequest.RequestType == QueryDomain:
			// try to get the lock of the requested domain
			ok := processor.tryGetLock(newRequest.Domains)
			switch {
			case ok:
				processor.workerChan <- newRequest
			case !ok:
				newRequest.ReturnChan <- UpdateResult{Err: ErrorResourceLocked}
			}
		// if one log picker thread completes the updating in memory, and wants to store the changes
		case newRequest.RequestType == UpdateDomain:
			processor.workerChan <- newRequest
		}

	}
}

// try to get the resources
func (processor *ConsistentDB) tryGetLock(domains [][32]byte) bool {
	processor.processingDomainsLock.Lock()
	defer processor.processingDomainsLock.Unlock()

	// check if any of the request domains is taken
	for _, v := range domains {
		_, ok := processor.processingDomains[v]
		if ok {
			return false
		}
	}

	// record the requested domain in the map
	for _, v := range domains {
		processor.processingDomains[v] = 1
	}
	return true
}

// remove locks in resources
func (processor *ConsistentDB) unlockDomain(domains [][32]byte) {
	processor.processingDomainsLock.Lock()
	defer processor.processingDomainsLock.Unlock()

	for _, v := range domains {
		delete(processor.processingDomains, v)
	}
}
