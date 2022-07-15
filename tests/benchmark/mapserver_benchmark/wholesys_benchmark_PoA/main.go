package main

import (
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
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/domain"
	"github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/responder"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
)

var domainCount int

// collect 1M certs, and update them
func main() {

	fmt.Println("new")

	testSet := []string{}

	for i := 0; i < 100000; i++ {
		testSet = append(testSet, getRandomDomainName(3))
	}

	domainCount = 0
	db.TruncateAllTablesWithoutTestObject()

	csvFile, err := os.Create("result.csv")
	respondeCSVFile, err := os.Create("result_responder.csv")
	//domainInfoFile, err := os.Create("domainInfo.csv")

	if err != nil {
		panic(err)
	}

	csvwriter := csv.NewWriter(csvFile)
	//domaincsvwriter := csv.NewWriter(domainInfoFile)
	responder_csvwriter := csv.NewWriter(respondeCSVFile)

	// new updater
	mapUpdater, err := updater.NewMapUpdater(nil, 233)
	if err != nil {
		panic(err)
	}
	ctx, cancelF := context.WithTimeout(context.Background(), 200*time.Minute)
	defer cancelF()

	// collect 100K certs
	mapUpdater.Fetcher.BatchSize = 40000
	const baseCTSize = 2*1000 + 1600000
	const count = 10000 * 1000
	mapUpdater.StartFetching("https://ct.googleapis.com/logs/argon2021",
		baseCTSize, baseCTSize+count-1)

	updateStart := time.Now()
	//names := []string{}
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

		domainCount = db.GetDomainNamesForTest()
		fmt.Println("total domains: ", domainCount)

		err = csvwriter.Write(append(append([]string{strconv.Itoa(i), timeToUpdateSMT.String()}, timeList...), strconv.Itoa(domainCount)))
		if err != nil {
			panic(err)
		}

		if i%5 == 4 {
			fetchProof(mapUpdater.GetRoot(), testSet, responder_csvwriter)
			//names = []string{}
		}

		csvwriter.Flush()
	}
	fmt.Println("************************ Update finished ******************************")
	fmt.Printf("time to get and update %d certs: %s\n", count, time.Since(updateStart))

	root := mapUpdater.GetRoot()
	err = mapUpdater.Close()
	if err != nil {
		panic(err)
	}

	err = os.WriteFile("root", root, 0644)
	if err != nil {
		panic(err)
	}
}

func fetchProof(root []byte, names []string, csv *csv.Writer) {
	ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancelF()

	const numOfWorkers = 1000
	const totalQueries = 5 * 100 * 1000

	depth := getTreeDepth()
	fmt.Println("tree depth:", depth)

	responder, err := responder.NewMapResponder(ctx, root, depth)
	if err != nil {
		panic(err)
	}

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

	fmt.Println(responderDuration, "for ", totalQueries, " queries")

	csv.Write([]string{
		responderDuration.String(),
	})
	csv.Flush()

	responder.Close()
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

func countSizeOfDomainProofs(proofs []*common.MapServerResponse) (int, int, int, int, int, int, int, int, int) {
	proofSize := 0
	domainSize := 0
	largeDomains10K := 0
	largeDomains50K := 0
	largeDomains100K := 0
	largeDomains200K := 0
	largeDomains500K := 0
	largeDomains1M := 0
	largeDomains5M := 0

	for _, proof := range proofs {
		for _, p := range proof.PoI.Proof {
			proofSize = len(p)
		}
		proofSize = proofSize + len(proof.PoI.ProofKey)
		proofSize = proofSize + len(proof.PoI.Root)
		proofSize = proofSize + len(proof.PoI.ProofValue)

		domainSize = domainSize + len(proof.DomainEntryBytes)
	}

	if domainSize > 5000*1024 {
		largeDomains5M++
	} else if domainSize > 1000*1024 {
		largeDomains1M++
	} else if domainSize > 500*1024 {
		largeDomains500K++
	} else if domainSize > 200*1024 {
		largeDomains200K++
	} else if domainSize > 100*1024 {
		largeDomains100K++
	} else if domainSize > 50*1024 {
		largeDomains50K++
	} else if domainSize > 10*1024 {
		largeDomains10K++
	}

	return proofSize, domainSize, largeDomains10K, largeDomains50K, largeDomains100K, largeDomains200K, largeDomains500K, largeDomains1M, largeDomains5M
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func getRandomDomainName(level int) string {
	result := ""
	for i := 0; i < level; i++ {
		b := make([]rune, 10)
		for i := range b {
			b[i] = letterRunes[rand.Intn(len(letterRunes))]
		}
		result = string(b) + "." + result
	}
	return result + "com"
}
