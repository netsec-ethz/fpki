package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"fmt"
	"math"
	"math/rand"
	"os"
	"strconv"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/netsec-ethz/fpki/pkg/domain"
	"github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/responder"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	dbtest "github.com/netsec-ethz/fpki/tests/pkg/db"
)

var domainCount int

// collect 1M certs, and update them
func main() {
	testSet6 := loadTestData("testData6.txt")
	testSet10 := loadTestData("testData10.txt")
	testSet20 := loadTestData("testData20.txt")
	testSet50 := loadTestData("testData50.txt")
	testSet100 := loadTestData("testData100.txt")
	testSet200 := loadTestData("testData200.txt")
	testSet500 := loadTestData("testData500.txt")
	testSet1000 := loadTestData("testData1000.txt")

	domainCount = 0
	dbtest.TruncateAllTablesWithoutTestObject()

	csvFile, err := os.Create("result.csv")
	csvPathFile, err := os.Create("pathResult.csv")

	//domainInfoFile, err := os.Create("domainInfo.csv")

	if err != nil {
		panic(err)
	}

	csvwriter := csv.NewWriter(csvFile)
	csvpathwriter := csv.NewWriter(csvPathFile)
	//domaincsvwriter := csv.NewWriter(domainInfoFile)

	// new updater
	mapUpdater, err := updater.NewMapUpdater(nil, 233)
	if err != nil {
		panic(err)
	}
	ctx, cancelF := context.WithTimeout(context.Background(), 200*time.Minute)
	defer cancelF()

	// collect 100K certs
	mapUpdater.Fetcher.BatchSize = 10000
	const baseCTSize = 2*1000 + 1600000
	const count = 1000 * 1000
	mapUpdater.StartFetching("https://ct.googleapis.com/logs/argon2021",
		baseCTSize, baseCTSize+count-1)

	updateStart := time.Now()

	for i := 0; ; i++ {
		fmt.Println()
		fmt.Println()
		fmt.Println(" ---------------------- batch ", i, " ---------------------------")

		n, timeList, _, err, _, _, _ := mapUpdater.UpdateNextBatchReturnTimeList(ctx)
		if err != nil {
			panic(err)
		}
		fmt.Println("number of certs: ", n)
		if n == 0 {
			break
		}

		start := time.Now()
		err = mapUpdater.CommitSMTChanges(ctx)
		if err != nil {
			panic(err)
		}
		fmt.Println("time to commit the changes: ", time.Since(start))
		timeToUpdateSMT := time.Since(start)

		domainCount = dbtest.GetDomainCountWithoutTestObject()
		fmt.Println("total domains: ", domainCount)

		err = csvwriter.Write(append(append([]string{strconv.Itoa(i), timeToUpdateSMT.String()}, timeList...), strconv.Itoa(domainCount)))
		if err != nil {
			panic(err)
		}

		ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancelF()

		responder, err := responder.NewMapResponder(ctx, mapUpdater.GetRoot(), 233, "./config/mapserver_config.json")
		if err != nil {
			panic(err)
		}

		totalPath := 0.0

		for i := 0; i < 10000; i++ {
			name := testSet6[rand.Intn(len(testSet6))]
			proofs, err := responder.GetProof(ctx, name)
			if err != nil {
				fmt.Println(err)
			}

			totalPath = totalPath + countPathSize(proofs)
		}

		fmt.Println(" size !!!!!!!!!!", totalPath/10000)

		responder.Close()

		csvwriter.Flush()
		csvpathwriter.Write([]string{fmt.Sprintf("%f", totalPath/10000.0), strconv.Itoa(domainCount)})
		csvpathwriter.Flush()
	}
	fmt.Println("************************ Update finished ******************************")
	fmt.Printf("time to get and update %d certs: %s\n", count, time.Since(updateStart))

	root := mapUpdater.GetRoot()
	err = mapUpdater.Close()
	if err != nil {
		panic(err)
	}

	depth := getTreeDepth()
	fmt.Println("tree depth:", depth)

	responder, err := responder.NewMapResponder(ctx, root, depth, "./config/mapserver_config.json")
	if err != nil {
		panic(err)
	}

	fetchProof(testSet6, "testSet6.csv", responder)
	fetchProof(testSet10, "testSet10.csv", responder)
	fetchProof(testSet20, "testSet20.csv", responder)
	fetchProof(testSet50, "testSet50.csv", responder)
	fetchProof(testSet100, "testSet100.csv", responder)
	fetchProof(testSet200, "testSet200.csv", responder)
	fetchProof(testSet500, "testSet500.csv", responder)
	fetchProof(testSet1000, "testSet1000.csv", responder)

	anaylseProofOverhead(testSet6, responder)
}

func anaylseProofOverhead(names []string, responder *responder.MapResponder) {
	ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancelF()

	totalSize := 0
	proofSize := 0
	totalCertificateSize := 0

	totalPath := 0.0

	for i := 0; i < 10000; i++ {
		name := names[rand.Intn(len(names))]
		proofs, err := responder.GetProof(ctx, name)
		if err != nil {
			fmt.Println(err)
		}

		newProofSize, newPOISize := countProofsSize(proofs)
		totalSize = totalSize + newProofSize
		proofSize = proofSize + newPOISize

		for _, proof := range proofs {
			if proof.PoI.ProofType == common.PoP {
				entry, err := common.DeserializeDomainEntry(proof.DomainEntryBytes)
				if err != nil {
					panic(err)
				}
				totalCertificateSize = totalCertificateSize + countCertSize(entry)
			}
		}

		totalPath = totalPath + countPathSize(proofs)
	}

	fmt.Println(totalSize, proofSize, totalCertificateSize, totalPath/10000.0)
}

func countPathSize(proofs []common.MapServerResponse) float64 {
	total := 0.0
	for _, proof := range proofs {
		total = total + float64(len(proof.PoI.Proof))
	}
	return total / float64(len(proofs))
}

func countCertSize(entry *common.DomainEntry) int {
	size := 0

	for _, caList := range entry.CAEntry {
		for _, certRaw := range caList.DomainCerts {
			size = size + len(certRaw)
		}
	}
	return size
}

func countPOISize(poi common.PoI) int {
	size := 0
	for _, proof := range poi.Proof {
		size = size + len(proof)
	}
	size = size + len(poi.Root)
	size = size + len(poi.ProofKey)
	size = size + len(poi.ProofValue)

	return size
}

func countProofsSize(proofs []common.MapServerResponse) (int, int) {
	size := 0
	proofSize := 0

	for _, proof := range proofs {
		size = size + countPOISize(proof.PoI) + len(proof.DomainEntryBytes)
		proofSize = proofSize + countPOISize(proof.PoI)
	}

	return size, proofSize
}

func fetchProof(names []string, resultFileName string, responder *responder.MapResponder) {
	respondeCSVFile, err := os.Create(resultFileName)
	if err != nil {
		panic(err)
	}

	responder_csvwriter := csv.NewWriter(respondeCSVFile)

	ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancelF()

	const numOfWorkers = 1000
	const totalQueries = 1 * 100 * 1000

	responderStartTime := time.Now()

	var wg sync.WaitGroup
	for w := 0; w < numOfWorkers; w++ {
		wg.Add(1)
		go func(queryCount int) {
			defer wg.Done()

			for i := 0; i < queryCount; i++ {
				name := names[rand.Intn(len(names))]
				_, err := responder.GetProof(ctx, name)
				if err != nil && err != domain.ErrInvalidDomainName {
					fmt.Println(err)
					continue
				}

			}
		}(totalQueries / numOfWorkers)
	}
	wg.Wait()

	responderDuration := time.Since(responderStartTime)

	fmt.Println(resultFileName, " ", responderDuration, "for ", totalQueries, " queries")

	responder_csvwriter.Write([]string{
		responderDuration.String(),
	})
	responder_csvwriter.Flush()

}

func loadTestData(fileName string) []string {
	testSet := []string{}

	f, err := os.Open(fileName)
	if err != nil {
		panic(err)
	}
	// remember to close the file at the end of the program
	defer f.Close()

	// read the file line by line using scanner
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		// do something with a line
		testSet = append(testSet, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		panic(err)
	}

	return testSet
}

func getTreeDepth() int {
	treeDepth := int(math.Log2(float64(domainCount)))
	fmt.Println("tree depth before: ", treeDepth)

	return 255 - treeDepth
}

func getUniqueName(names []string) []string {
	uniqueSet := make(map[string]struct{})
	for _, name := range names {
		uniqueSet[name] = struct{}{}
	}

	result := []string{}

	for k := range uniqueSet {
		result = append(result, k)
	}
	return result
}

func checkPoP(input []*common.MapServerResponse) bool {
	for _, pair := range input {
		if pair.PoI.ProofType == common.PoP {
			if len(pair.DomainEntryBytes) == 0 {
				panic("result error")
			}
			return true
		}
	}
	return false
}
