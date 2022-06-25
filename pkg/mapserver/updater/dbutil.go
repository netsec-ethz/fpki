package updater

import (
	"context"
	"fmt"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	mapCommon "github.com/netsec-ethz/fpki/pkg/mapserver/common"
)

const batchSize = 1000

type dbResult struct {
	pairs []*db.KeyValuePair
	err   error
}

// retrieveAffectedDomainFromDB: get affected domain entries from db
func (mapUpdater *MapUpdater) retrieveAffectedDomainFromDB(ctx context.Context,
	affectedDomainsMap uniqueSet) (map[common.SHA256Output]*mapCommon.DomainEntry, error) {

	// XXX(juagargi) review why passing a set (we need to convert it to a slice)
	// list of domain hashes to fetch the domain entries from db
	affectedDomainHashes := make([]common.SHA256Output, 0, len(affectedDomainsMap))
	for k := range affectedDomainsMap {
		affectedDomainHashes = append(affectedDomainHashes, k)
	}

	work := func(domainHashes []common.SHA256Output, resultChan chan dbResult) {
		domainEntries, err := mapUpdater.dbConn.RetrieveDomainEntries(ctx, domainHashes)
		resultChan <- dbResult{pairs: domainEntries, err: err}
	}

	resultChan := make(chan dbResult)

	totalNum := len(affectedDomainHashes)
	numOfWorker := totalNum / batchSize
	remaining := totalNum % batchSize

	workerCounter := 0
	for i := 0; i < numOfWorker; i++ {
		workerCounter++
		go work(affectedDomainHashes[i*batchSize:i*batchSize+batchSize], resultChan)
	}
	if remaining != 0 {
		workerCounter++
		go work(affectedDomainHashes[numOfWorker*batchSize:], resultChan)
	}

	domainEntries := []*db.KeyValuePair{}

	for workerCounter > 0 {
		newResult := <-resultChan
		if newResult.err != nil {
			return nil, newResult.err
		}
		//fmt.Println("pair length ", len(newResult.pairs))
		domainEntries = append(domainEntries, newResult.pairs...)
		workerCounter--
	}

	start := time.Now()

	//fmt.Println(len(domainEntries))
	// parse the key-value pair -> domain map
	domainEntriesMap, err := parseDomainBytes(domainEntries)
	if err != nil {
		return nil, fmt.Errorf("retrieveAffectedDomainFromDB | %w", err)
	}
	end := time.Now()
	fmt.Println("time to parse domain entries", end.Sub(start))
	//fmt.Println(len(domainEntriesMap))
	return domainEntriesMap, nil
}

// writeChangesToDB: commit changes to domain entries table and updates table
func (mapUpdater *MapUpdater) writeChangesToDB(ctx context.Context,
	updatesToDomainEntriesTable []*db.KeyValuePair) (int, error) {

	_, err := mapUpdater.dbConn.UpdateDomainEntries(ctx, updatesToDomainEntriesTable)
	if err != nil {
		return 0, fmt.Errorf("writeChangesToDB | %w", err)
	}

	return len(updatesToDomainEntriesTable), nil
}

const domainParserWorker = 64

type parserResult struct {
	keys    [][32]byte
	entries []*mapCommon.DomainEntry
	err     error
}

// domain bytes -> domain entries
func parseDomainBytes(domainEntries []*db.KeyValuePair) (
	map[common.SHA256Output]*mapCommon.DomainEntry, error) {
	/*
		unique := make(map[[32]byte]byte)
		for _, v := range domainEntries {
			unique[v.Key] = 1
		}
		fmt.Println(len(unique))
	*/
	if len(domainEntries) == 0 {
		return make(map[common.SHA256Output]*mapCommon.DomainEntry), nil
	}

	workerNum := domainParserWorker
	count := len(domainEntries)

	if count < 64 {
		workerNum = 1
	}

	step := count / workerNum
	remaining := count % workerNum

	resultChan := make(chan parserResult)

	work := func(domainBytes []*db.KeyValuePair) {
		entries := []*mapCommon.DomainEntry{}
		keys := [][32]byte{}
		for _, entry := range domainBytes {
			newPair, err := mapCommon.DeserializeDomainEntry(entry.Value)
			if err != nil {
				resultChan <- parserResult{err: err}
			}
			entries = append(entries, newPair)
			keys = append(keys, entry.Key)
		}
		resultChan <- parserResult{keys: keys, entries: entries}
	}

	activeWorker := 0
	for i := 0; i < workerNum; i++ {
		activeWorker++
		//fmt.Println(i*step, "    ", i*step+step-1)
		go work(domainEntries[i*step : i*step+step])
	}
	if remaining != 0 {
		activeWorker++
		//fmt.Println(workerNum * step)
		go work(domainEntries[workerNum*step:])
	}

	//fmt.Println(activeWorker)

	entries := []*mapCommon.DomainEntry{}
	keys := [][32]byte{}

	for activeWorker > 0 {
		threadResult := <-resultChan
		if threadResult.err != nil {
			return nil, fmt.Errorf("parseDomainBytes | %w", threadResult.err)
		}
		entries = append(entries, threadResult.entries...)
		keys = append(keys, threadResult.keys...)
		activeWorker--
		//fmt.Println(activeWorker)
	}

	result := make(map[common.SHA256Output]*mapCommon.DomainEntry)
	//fmt.Println(len(entries))

	for i, k := range entries {
		result[keys[i]] = k
	}

	if len(domainEntries) != len(result) {
		fmt.Println(len(domainEntries), " ", len(result))
		return nil, fmt.Errorf("parseDomainBytes | incomplete parsing")
	}

	return result, nil
}
