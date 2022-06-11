package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/netsec-ethz/fpki/pkg/domain"
	"github.com/netsec-ethz/fpki/pkg/mapserver/responder"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"

	_ "github.com/go-sql-driver/mysql"
	ct "github.com/google/certificate-transparency-go"
	ctTls "github.com/google/certificate-transparency-go/tls"
	ctX509 "github.com/google/certificate-transparency-go/x509"
)

var wg sync.WaitGroup
var root []byte
var domainMap map[string]byte

func main() {
	domainMap = make(map[string]byte)
	truncateTable()
	doUpdater()
	doResponder()
	truncateTable()
}

func doUpdater() {
	// new updater
	mapUpdater, err := updater.NewMapUpdater(nil, 233)
	if err != nil {
		panic(err)
	}

	updateStart := time.Now()
	// collect 1M certs
	for i := 0; i < 100; i++ {

		ctx, cancelF := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancelF()

		fmt.Println()
		fmt.Println()
		fmt.Println(" ---------------------- Iteration ", i, " ---------------------------")
		wholeStart := time.Now()
		start := time.Now()
		err = mapUpdater.UpdateCerts(ctx, "https://ct.googleapis.com/logs/argon2021",
			2000000+i*10000, 2009999+i*10000)
		if err != nil {
			panic(err)
		}
		end := time.Now()

		start = time.Now()
		err = mapUpdater.CommitSMTChanges(ctx)
		if err != nil {
			panic(err)
		}
		end = time.Now()

		wholeEnd := time.Now()
		fmt.Println()
		fmt.Println("***********************************")
		fmt.Println("Total time: ", wholeEnd.Sub(wholeStart))
		fmt.Println("time to update the changes: ", end.Sub(start))
		fmt.Println("time to commit the changes to SMT: ", end.Sub(start))
		fmt.Println("***********************************")

	}
	updateEnd := time.Now()
	fmt.Println("************************ Update finished ******************************")
	fmt.Println("time to get and update 1M certs: ", updateEnd.Sub(updateStart))

	root = mapUpdater.GetRoot()

	err = mapUpdater.Close()
	if err != nil {
		panic(err)
	}
}

func doResponder() {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	// only use one responder
	responder, err := responder.NewMapResponder(ctx, root, 233, 10)
	if err != nil {
		panic(err)
	}

	// collect 10,000 certs, for proof fetching
	collectedCerts := []ctX509.Certificate{}
	for i := 0; i < 2500; i++ {
		certList, err := getCerts("https://ct.googleapis.com/logs/argon2021", int64(2000000+i*20), int64(2000000+i*20+19))
		fmt.Println("downloading : ", int64(2500000+i*20), " - ", int64(2500000+i*20+19))
		if err != nil {
			panic(err)
		}
		for _, cert := range certList {
			collectedCerts = append(collectedCerts, cert)
		}
	}

	numOfWorker := 20

	step := len(collectedCerts) / numOfWorker
	fetchStartTime := time.Now()

	wg.Add(numOfWorker)
	for i := 0; i < numOfWorker; i++ {
		go collectProof(responder, collectedCerts[i*step:i*step+step-1])
	}
	wg.Wait()

	fetchEndTime := time.Now()
	fmt.Println("time to fetch proofs: ", fetchEndTime.Sub(fetchStartTime))
}

func truncateTable() {
	db, err := sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/fpki?maxAllowedPacket=1073741824")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	// truncate table
	_, err = db.Exec("TRUNCATE fpki.domainEntries;")
	if err != nil {
		panic(err)
	}

	// truncate table
	_, err = db.Exec("TRUNCATE fpki.tree;")
	if err != nil {
		panic(err)
	}

	// truncate table
	_, err = db.Exec("TRUNCATE fpki.updates;")
	if err != nil {
		panic(err)
	}

	err = db.Close()
	if err != nil {
		panic(err)
	}
}

// CertData: merkle tree leaf
type CertData struct {
	LeafInput string `json:"leaf_input"`
	ExtraData string `json:"extra_data"`
}

// CertLog: Data from CT log
type CertLog struct {
	Entries []CertData
}

// copy of function from logpicker_worker.go
func getCerts(ctURL string, start int64, end int64) ([]ctX509.Certificate, error) {
	url := fmt.Sprintf(ctURL+"/ct/v1/get-entries?start=%d&end=%d&quot", start, end)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("http.Get %w", err)
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)

	var resultsCerLog CertLog
	json.Unmarshal(buf.Bytes(), &resultsCerLog)

	certList := []ctX509.Certificate{}

	// parse merkle leaves and append it to the result
parse_cert_loop:
	for _, entry := range resultsCerLog.Entries {
		leafBytes, _ := base64.RawStdEncoding.DecodeString(entry.LeafInput)
		var merkleLeaf ct.MerkleTreeLeaf
		ctTls.Unmarshal(leafBytes, &merkleLeaf)

		var certificate *ctX509.Certificate
		switch entryType := merkleLeaf.TimestampedEntry.EntryType; entryType {
		case ct.X509LogEntryType:
			certificate, err = ctX509.ParseCertificate(merkleLeaf.TimestampedEntry.X509Entry.Data)
			if err != nil {
				fmt.Println("ERROR: ParseCertificate ", err)
				continue parse_cert_loop
			}
		case ct.PrecertLogEntryType:
			certificate, err = ctX509.ParseTBSCertificate(merkleLeaf.TimestampedEntry.PrecertEntry.TBSCertificate)
			if err != nil {
				fmt.Println("ERROR: ParseTBSCertificate ", err)
				continue parse_cert_loop
			}
		}

		//fmt.Println("-------------------------------------")
		//fmt.Println(certificate.Subject.CommonName)
		//fmt.Println(certificate.DNSNames)
		certList = append(certList, *certificate)
	}
	return certList, nil
}

func collectProof(responder *responder.MapResponder, certs []ctX509.Certificate) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	numOfQuery := 0
	for _, cert := range certs {
		if cert.Subject.CommonName != "" {
			_, err := responder.GetProof(ctx, cert.Subject.CommonName)
			if err != nil && err != domain.InvalidDomainNameErr {
				panic(err)
			}
		}
		numOfQuery++
	}
	fmt.Println("finished !", numOfQuery)
	wg.Done()
}
