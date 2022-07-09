package main

import (
	"context"
	"database/sql"
	"encoding/csv"
	"fmt"
	"math"
	"os"
	"strconv"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/responder"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
)

var domainCount int

// collect 1M certs, and update them
func main() {

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
	const count = 5000 * 1000
	mapUpdater.StartFetching("https://ct.googleapis.com/logs/argon2021",
		baseCTSize, baseCTSize+count-1)

	updateStart := time.Now()
	names := []string{}
	for i := 0; ; i++ {
		fmt.Println()
		fmt.Println()
		fmt.Println(" ---------------------- batch ", i, " ---------------------------")

		n, timeList, newNames, err := mapUpdater.UpdateNextBatchReturnTimeList(ctx)
		if err != nil {
			panic(err)
		}
		fmt.Println("number of certs: ", n)
		if n == 0 {
			break
		}

		names = append(names, newNames...)

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

		fmt.Println(mapUpdater.GetRoot())

		if i%5 == 4 {
			fetchProof(mapUpdater.GetRoot(), getUniqueName(names), responder_csvwriter)
			names = []string{}
		}

		//if i%10 == 9 {
		//	getDomainInfo(domainCount, domaincsvwriter)
		//}

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

	batch := 2000

	count := len(names)

	workerCount := count / batch

	count = workerCount * batch

	fmt.Println()
	fmt.Println()
	fmt.Println("**********************************************************")
	fmt.Println("num of fetchings: ", count)

	depth := getTreeDepth()
	fmt.Println("tree depth:", depth)

	responder, err := responder.NewMapResponder(ctx, root, depth)
	if err != nil {
		panic(err)
	}
	wg := &sync.WaitGroup{}

	t1 := time.Now()

	readSize := 0
	readLock := &sync.Mutex{}

	proofSize := 0
	domainSize := 0
	totalSize := 0

	sizeReadLock := &sync.Mutex{}

	work := func(names []string) {
		domains, newReadSize, err := responder.GetDomainProofsTest(ctx, names)
		if err != nil {
			panic(err)
		}

		readLock.Lock()
		readSize = readSize + newReadSize
		readLock.Unlock()

		pSizeT := 0
		dSizeT := 0

		for _, domain := range domains {
			pSize, dSize, _, _, _, _, _, _, _ := countSizeOfDomainProofs(domain)
			pSizeT = pSizeT + pSize
			dSizeT = dSizeT + dSize

			if !checkPoP(domain) {
				panic("proof error!!!!!!")
			}
		}
		sizeReadLock.Lock()
		proofSize = proofSize + pSizeT
		domainSize = domainSize + dSizeT
		totalSize = totalSize + pSizeT + dSizeT

		sizeReadLock.Unlock()
		wg.Done()
	}

	wg.Add(workerCount)

	for i := 0; i < workerCount; i++ {
		go work(names[i*batch : i*batch+batch])
	}
	wg.Wait()

	t2 := time.Now()
	fmt.Println(t2.Sub(t1))
	speed := float64(count) / float64(t2.Sub(t1).Seconds())
	fmt.Println("speed: ", speed)
	fmt.Println("total read size: ", readSize/1024, " KB")
	fmt.Println("proof size: ", proofSize/1024, " KB")
	fmt.Println("domain size: ", domainSize/1024, " KB")
	fmt.Println("avg domain size: ", domainSize/(1024*count), " KB")
	fmt.Println()
	fmt.Println("**********************************************************")
	fmt.Println()
	fmt.Println()

	csv.Write([]string{
		t2.Sub(t1).String(),
		strconv.Itoa(count),
		fmt.Sprintf("%f", speed),
		strconv.Itoa(readSize),
		strconv.Itoa(proofSize),
		strconv.Itoa(domainSize),
	})
	csv.Flush()

	responder.Close()
	/*
		ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancelF()

		batch := 2000

		count := len(names)

		workerCount := count / batch

		count = workerCount * batch

		fmt.Println()
		fmt.Println()
		fmt.Println("**********************************************************")
		fmt.Println("num of fetchings: ", count)

		depth := getTreeDepth()
		fmt.Println("tree length:", depth)

		responder, err := responder.NewMapResponder(ctx, root, depth)
		if err != nil {
			panic(err)
		}
		wg := &sync.WaitGroup{}

		t1 := time.Now()

		readSize := 0
		readLock := &sync.Mutex{}

		proofSize := 0
		domainSize := 0
		totalSize := 0

		largeDomains10K := 0
		largeDomains50K := 0
		largeDomains100K := 0
		largeDomains200K := 0
		largeDomains500K := 0
		largeDomains1M := 0
		largeDomains5M := 0

		sizeReadLock := &sync.Mutex{}

		work := func(names []string) {
			domains, newReadSize, err := responder.GetDomainProofsTest(ctx, names)
			if err != nil {
				panic(err)
			}

			readLock.Lock()
			readSize = readSize + newReadSize
			readLock.Unlock()

			pSizeT := 0
			dSizeT := 0

			T10K := 0
			T50K := 0
			T100K := 0
			T200K := 0
			T500K := 0
			T1M := 0
			T5M := 0

			for _, domain := range domains {
				pSize, dSize, L10K, L50K, L100K, L200K, L500K, L1M, L5M := countSizeOfDomainProofs(domain)
				pSizeT = pSizeT + pSize
				dSizeT = dSizeT + dSize

				T10K = T10K + L10K
				T50K = T50K + L50K
				T100K = T100K + L100K
				T200K = T200K + L200K
				T500K = T500K + L500K
				T1M = T1M + L1M
				T5M = T5M + L5M

			}
			sizeReadLock.Lock()
			proofSize = proofSize + pSizeT
			domainSize = domainSize + dSizeT
			totalSize = totalSize + pSizeT + dSizeT

			largeDomains10K = largeDomains10K + T10K
			largeDomains50K = largeDomains50K + T50K
			largeDomains100K = largeDomains100K + T100K
			largeDomains200K = largeDomains200K + T200K
			largeDomains500K = largeDomains500K + T500K
			largeDomains1M = largeDomains1M + T1M
			largeDomains5M = largeDomains5M + T5M

			sizeReadLock.Unlock()
			wg.Done()
		}

		wg.Add(workerCount)

		for i := 0; i < workerCount; i++ {
			go work(names[i*batch : i*batch+batch])
		}
		wg.Wait()

		t2 := time.Now()
		fmt.Println(t2.Sub(t1))
		speed := float64(count) / float64(t2.Sub(t1).Seconds())
		fmt.Println("speed: ", speed)
		fmt.Println("total read size: ", readSize/1024, " KB")
		fmt.Println("proof size: ", proofSize/1024, " KB")
		fmt.Println("domain size: ", domainSize/1024, " KB")
		fmt.Println("avg domain size: ", domainSize/(1024*count), " KB")
		fmt.Println()
		fmt.Println(" 10K: ", largeDomains10K)
		fmt.Println(" 50K: ", largeDomains50K)
		fmt.Println(" 100K: ", largeDomains100K)
		fmt.Println(" 200K: ", largeDomains200K)
		fmt.Println(" 500K: ", largeDomains500K)
		fmt.Println(" 1M: ", largeDomains1M)
		fmt.Println(" 5M: ", largeDomains5M)
		fmt.Println("**********************************************************")
		fmt.Println()
		fmt.Println()

		csv.Write([]string{
			t2.Sub(t1).String(),
			strconv.Itoa(count),
			fmt.Sprintf("%f", speed),
			strconv.Itoa(readSize/1024) + " KB",
			strconv.Itoa(proofSize),
			strconv.Itoa(domainSize),
			strconv.Itoa(largeDomains10K),
			strconv.Itoa(largeDomains50K),
			strconv.Itoa(largeDomains100K),
			strconv.Itoa(largeDomains200K),
			strconv.Itoa(largeDomains500K),
			strconv.Itoa(largeDomains1M),
			strconv.Itoa(largeDomains5M),
		})
		csv.Flush()

		responder.Close()
	*/
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

	/*
		if domainSize == 19654521 {
			for _, proof := range proofs {
				domainEntry, err := common.DeserializeDomainEntry(proof.DomainEntryBytes)
				if err != nil {
					panic(err)
				}
				for _, caList := range domainEntry.CAEntry {
					fmt.Println(caList.CAName)
					for _, certBytes := range caList.DomainCerts {

						cert, err := ctx509.ParseTBSCertificate(certBytes)
						if err != nil {
							panic("failed to parse certificate: " + err.Error())
						}
						fmt.Println("-----------------------------")
						fmt.Println(cert.Subject.CommonName)
						fmt.Println(cert.DNSNames)
						fmt.Println("-----------------------------")
					}
				}
			}
			fmt.Println("large domains: ", domainSize)
	*/

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

func getDomainInfo(count int, csv *csv.Writer) {
	db, err := sql.Open("mysql", "root@tcp(localhost)/fpki")
	if err != nil {
		panic(err)
	}
	fmt.Println("total domain count: ", count)

	var size11 int
	err = db.QueryRow("SELECT COUNT(*) from domainEntries WHERE length(value)>1*1024;").Scan(&size11)
	if err != nil {
		panic(err)
	}
	fmt.Println("1KB ", size11)

	var size12 int
	err = db.QueryRow("SELECT COUNT(*) from domainEntries WHERE length(value)>2*1024;").Scan(&size12)
	if err != nil {
		panic(err)
	}
	fmt.Println("2KB ", size12)

	var size13 int
	err = db.QueryRow("SELECT COUNT(*) from domainEntries WHERE length(value)>3*1024;").Scan(&size13)
	if err != nil {
		panic(err)
	}
	fmt.Println("3KB ", size13)

	var size14 int
	err = db.QueryRow("SELECT COUNT(*) from domainEntries WHERE length(value)>4*1024;").Scan(&size14)
	if err != nil {
		panic(err)
	}
	fmt.Println("4KB ", size14)

	var size15 int
	err = db.QueryRow("SELECT COUNT(*) from domainEntries WHERE length(value)>5*1024;").Scan(&size15)
	if err != nil {
		panic(err)
	}
	fmt.Println("5KB ", size15)

	var size16 int
	err = db.QueryRow("SELECT COUNT(*) from domainEntries WHERE length(value)>7*1024;").Scan(&size16)
	if err != nil {
		panic(err)
	}
	fmt.Println("7KB ", size16)

	var size17 int
	err = db.QueryRow("SELECT COUNT(*) from domainEntries WHERE length(value)>8*1024;").Scan(&size17)
	if err != nil {
		panic(err)
	}
	fmt.Println("8KB ", size17)

	var size1 int
	err = db.QueryRow("SELECT COUNT(*) from domainEntries WHERE length(value)>10*1024;").Scan(&size1)
	if err != nil {
		panic(err)
	}
	fmt.Println("10K ", size1)

	var size2 int
	err = db.QueryRow("SELECT COUNT(*) from domainEntries WHERE length(value)>20*1024;").Scan(&size2)
	if err != nil {
		panic(err)
	}
	fmt.Println("20K ", size2)

	var size3 int
	err = db.QueryRow("SELECT COUNT(*) from domainEntries WHERE length(value)>50*1024;").Scan(&size3)
	if err != nil {
		panic(err)
	}
	fmt.Println("50K ", size3)

	var size4 int
	err = db.QueryRow("SELECT COUNT(*) from domainEntries WHERE length(value)>100*1024;").Scan(&size4)
	if err != nil {
		panic(err)
	}
	fmt.Println("100K ", size4)

	var size5 int
	err = db.QueryRow("SELECT COUNT(*) from domainEntries WHERE length(value)>200*1024;").Scan(&size5)
	if err != nil {
		panic(err)
	}
	fmt.Println("200K ", size5)

	var size6 int
	err = db.QueryRow("SELECT COUNT(*) from domainEntries WHERE length(value)>500*1024;").Scan(&size6)
	if err != nil {
		panic(err)
	}
	fmt.Println("500K ", size6)

	var size7 int
	err = db.QueryRow("SELECT COUNT(*) from domainEntries WHERE length(value)>1024*1024;").Scan(&size7)
	if err != nil {
		panic(err)
	}
	fmt.Println("1M ", size7)

	var size8 int
	err = db.QueryRow("SELECT COUNT(*) from domainEntries WHERE length(value)>2*1024*1024;").Scan(&size8)
	if err != nil {
		panic(err)
	}
	fmt.Println("2M ", size8)

	var size9 int
	err = db.QueryRow("SELECT COUNT(*) from domainEntries WHERE length(value)>5*1024*1024;").Scan(&size9)
	if err != nil {
		panic(err)
	}
	fmt.Println("5M ", size9)

	var size10 int
	err = db.QueryRow("SELECT COUNT(*) from domainEntries WHERE length(value)>10*1024*1024;").Scan(&size10)
	if err != nil {
		panic(err)
	}
	fmt.Println("10M ", size10)

	csv.Write([]string{
		strconv.Itoa(count),
		strconv.Itoa(size11),
		strconv.Itoa(size12),
		strconv.Itoa(size13),
		strconv.Itoa(size14),
		strconv.Itoa(size15),
		strconv.Itoa(size16),
		strconv.Itoa(size17),
		strconv.Itoa(size1),
		strconv.Itoa(size2),
		strconv.Itoa(size3),
		strconv.Itoa(size4),
		strconv.Itoa(size5),
		strconv.Itoa(size6),
		strconv.Itoa(size7),
		strconv.Itoa(size8),
		strconv.Itoa(size9),
		strconv.Itoa(size10),
	})
	csv.Flush()

	db.Close()
}

/*

func fetchProof(root []byte, names []string) {
	ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancelF()

	count := len(names)
	fmt.Println("**********************************************************")
	fmt.Println("num of fetchings: ", count)

	responder, err := responder.NewMapResponder(ctx, root, 233)
	if err != nil {
		panic(err)
	}

	t1 := time.Now()

	parallelRequestLimit := count%1000
	wg := &sync.WaitGroup{}
	var numRequests int64 = 0
	var domainData int64 = 0
	work := func(count int, names []string) {
		defer wg.Done()
		for i := 0; i < count; i++ {
			name := names[rand.Intn(len(names))]
			responses, err := responder.GetProof(ctx, name)
			if err != nil {
				panic(err)
			}

			atomic.AddInt64(&numRequests, 1)
			for _, p := range responses {
				atomic.AddInt64(&domainData, int64(len(p.DomainEntryBytes)))
			}
		}
	}
	wg.Add(parallelRequestLimit)
	i := 0
	for ; i < count%parallelRequestLimit; i++ {
		go work(count/parallelRequestLimit+1, names)
	}
	for ; i < parallelRequestLimit; i++ {
		go work(count/parallelRequestLimit, names)
	}
	wg.Wait()

	t2 := time.Now()
	fmt.Println(t2.Sub(t1))
	fmt.Println("**********************************************************")

	err = responder.Close()
	if err != nil {
		panic(err)
	}
}

func getUniqueName(names []string) []string {
	uniqueSet := make(map[string]struct{})
	for _, name := range names {
		uniqueSet[name] = struct{}{}
	}

	result := []string{}

	for k, _ := range uniqueSet {
		result = append(result, k)
	}
	return result
}
*/
