package updater

import (
	"context"
	"fmt"
	"time"

	"github.com/google/certificate-transparency-go/x509"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/domain"
	mapCommon "github.com/netsec-ethz/fpki/pkg/mapserver/common"
)

// deleteme! only used to print extra info in benchmarks:
// functions for measuring the bottlemeck

func (u *MapUpdater) UpdateNextBatchReturnTimeList(ctx context.Context) (int, []string, []string, error, []*db.KeyValuePair, []*db.KeyValuePair, int) {
	certs, err := u.Fetcher.NextBatch(ctx)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("CollectCerts | GetCertMultiThread | %w", err), nil, nil, 0
	}
	names := parseCertDomainName(certs)
	timeList, err, writePair, readPair, smtSize := u.updateCertsReturnTime(ctx, certs)
	return len(certs), timeList, names, err, writePair, readPair, smtSize
}

func (mapUpdater *MapUpdater) updateCertsReturnTime(ctx context.Context, certs []*ctx509.Certificate) (
	[]string, error, []*db.KeyValuePair, []*db.KeyValuePair, int) {

	timeList := []string{}
	totalStart := time.Now()
	start := time.Now()
	keyValuePairs, _, times, err, writePairs, readPairs :=
		mapUpdater.UpdateDomainEntriesTableUsingCertsReturnTime(ctx, certs)
	if err != nil {
		return nil, fmt.Errorf("CollectCerts | UpdateDomainEntriesUsingCerts | %w", err), nil, nil, 0
	}
	end := time.Now()
	fmt.Println()
	fmt.Println("============================================")
	fmt.Println("(db and memory) time to update domain entries: ", end.Sub(start))
	timeList = append(timeList, end.Sub(start).String())

	if len(keyValuePairs) == 0 {
		return nil, nil, []*db.KeyValuePair{}, []*db.KeyValuePair{}, 0
	}

	keyInput, valueInput, err := keyValuePairToSMTInput(keyValuePairs)
	if err != nil {
		return nil, fmt.Errorf("CollectCerts | keyValuePairToSMTInput | %w", err), nil, nil, 0
	}

	start = time.Now()
	_, err = mapUpdater.smt.Update(ctx, keyInput, valueInput)
	if err != nil {
		return nil, fmt.Errorf("CollectCerts | Update | %w", err), nil, nil, 0
	}
	end = time.Now()

	fmt.Println()
	fmt.Println("============================================")
	fmt.Println("(memory) time to update tree in memory: ", end.Sub(start))
	timeList = append(timeList, end.Sub(start).String())

	totalEnd := time.Now()

	timeList = append(timeList, totalEnd.Sub(totalStart).String())
	timeList = append(timeList, times...)

	return timeList, nil, writePairs, readPairs, len(keyInput)
}

// UpdateDomainEntriesTableUsingCerts: Update the domain entries using the domain certificates
func (mapUpdater *MapUpdater) UpdateDomainEntriesTableUsingCertsReturnTime(ctx context.Context,
	certs []*x509.Certificate) ([]*db.KeyValuePair, int, []string, error, []*db.KeyValuePair, []*db.KeyValuePair) {

	timeList := []string{}
	if len(certs) == 0 {
		return nil, 0, nil, nil, nil, nil
	}

	start := time.Now()
	// get the unique list of affected domains
	affectedDomainsMap, domainCertMap := getAffectedDomainAndCertMap(certs)
	end := time.Now()
	fmt.Println("(memory) time to process certs: ", end.Sub(start))
	timeList = append(timeList, end.Sub(start).String())

	// if no domain to update
	if len(affectedDomainsMap) == 0 {
		return nil, 0, nil, nil, nil, nil
	}

	start = time.Now()
	// retrieve (possibly)affected domain entries from db
	// It's possible that no records will be changed, because the certs are already recorded.
	domainEntriesMap, readData, err := mapUpdater.retrieveAffectedDomainFromDBReturnReadDomains(ctx, affectedDomainsMap)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("UpdateDomainEntriesTableUsingCerts | retrieveAffectedDomainFromDB | %w", err), nil, nil
	}
	end = time.Now()
	fmt.Println("(db)     time to retrieve domain entries: ", end.Sub(start))
	timeList = append(timeList, end.Sub(start).String())

	start = time.Now()
	// update the domain entries
	updatedDomains, err := updateDomainEntries(domainEntriesMap, domainCertMap)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("UpdateDomainEntriesTableUsingCerts | updateDomainEntries | %w", err), nil, nil
	}
	end = time.Now()
	fmt.Println("(db)     time to update domain entries: ", end.Sub(start))
	timeList = append(timeList, end.Sub(start).String())

	// if during this updates, no cert is added, directly return
	if len(updatedDomains) == 0 {
		return nil, 0, nil, nil, nil, nil
	}

	start = time.Now()
	// get the domain entries only if they are updated, from DB
	domainEntriesToWrite, err := getDomainEntriesToWrite(updatedDomains, domainEntriesMap)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("UpdateDomainEntriesTableUsingCerts | getDomainEntriesToWrite | %w", err), nil, nil
	}

	// serialized the domainEntry -> key-value pair
	keyValuePairs, err := serializeUpdatedDomainEntries(domainEntriesToWrite)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("UpdateDomainEntriesTableUsingCerts | serializeUpdatedDomainEntries | %w", err), nil, nil
	}
	end = time.Now()
	fmt.Println("(memory) time to process updated domains: ", end.Sub(start))
	timeList = append(timeList, end.Sub(start).String())

	start = time.Now()
	// commit changes to db
	num, err := mapUpdater.writeChangesToDB(ctx, keyValuePairs)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("UpdateDomainEntriesTableUsingCerts | writeChangesToDB | %w", err), nil, nil
	}
	end = time.Now()
	fmt.Println("(db)     time to write updated domain entries: ", end.Sub(start))
	timeList = append(timeList, end.Sub(start).String())

	return keyValuePairs, num, timeList, nil, keyValuePairs, readData
}

func countDBWriteSize(keyValuePairs []*db.KeyValuePair) int {
	totalSize := 0
	for _, pair := range keyValuePairs {
		totalSize = totalSize + len(pair.Value)
		totalSize = totalSize + len(pair.Key)
	}
	return totalSize
}

func parseCertDomainName(certs []*ctx509.Certificate) []string {
	result := []string{}
	for _, cert := range certs {
		_, err := domain.ParseDomainName(cert.Subject.CommonName)
		if err == nil {
			result = append(result, cert.Subject.CommonName)
		}
	}
	return result
}

// retrieveAffectedDomainFromDB: get affected domain entries from db
func (mapUpdater *MapUpdater) retrieveAffectedDomainFromDBReturnReadDomains(ctx context.Context,
	affectedDomainsMap uniqueSet) (map[common.SHA256Output]*mapCommon.DomainEntry, []*db.KeyValuePair, error) {

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
			return nil, nil, newResult.err
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
		return nil, nil, fmt.Errorf("retrieveAffectedDomainFromDB | %w", err)
	}
	end := time.Now()
	fmt.Println("time to parse domain entries", end.Sub(start))
	//fmt.Println(len(domainEntriesMap))
	return domainEntriesMap, domainEntries, nil
}
