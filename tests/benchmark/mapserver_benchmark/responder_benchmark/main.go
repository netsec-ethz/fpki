package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	ct "github.com/google/certificate-transparency-go"
	ctTls "github.com/google/certificate-transparency-go/tls"
	ctX509 "github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/domain"
	"github.com/netsec-ethz/fpki/pkg/mapserver/responder"
)

var wg sync.WaitGroup

func main() {
	/*
		db, err := sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/fpki?maxAllowedPacket=1073741824")
		defer db.Close()
		if err != nil {
			panic(err)
		}

		// truncate table
		_, err = db.Exec("TRUNCATE `fpki`.`domainEntries`;")
		if err != nil {
			panic(err)
		}

		// truncate table
		_, err = db.Exec("TRUNCATE `fpki`.`tree`;")
		if err != nil {
			panic(err)
		}

		// truncate table
		_, err = db.Exec("TRUNCATE `fpki`.`updates`;")
		if err != nil {
			panic(err)
		}

		// new updater
		mapUpdater, err := updater.NewMapUpdater(nil, 233)
		if err != nil {
			panic(err)
		}

		updateStart := time.Now()

		ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
		defer cancelF()

		err = mapUpdater.UpdateFromCT(ctx, "https://ct.googleapis.com/logs/argon2021", int64(2500000), int64(2509999))
		if err != nil {
			panic(err)
		}

		err = mapUpdater.CommitChanges(ctx)
		if err != nil {
			panic(err)
		}

		updateEnd := time.Now()
		fmt.Println("************************ Update finished ******************************")
		fmt.Println("time to get and update 10,000 certs: ", updateEnd.Sub(updateStart))

		root := mapUpdater.GetRoot()
		err = mapUpdater.Close()
		if err != nil {
			panic(err)
		}
	*/
	// only use one responder
	root, err := os.ReadFile("root")
	if err != nil {
		panic(err)
	}
	ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancelF()

	responder, err := responder.NewMapResponder(ctx, root, 233, 10)

	// collect 10,000 certs, for proof fetching
	collectedCerts := []ctX509.Certificate{}
	for i := 0; i < 500; i++ {
		certList, err := getCerts("https://ct.googleapis.com/logs/argon2021", int64(2500000+i*20), int64(2500000+i*20+19))
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
		//fmt.Println(numOfQuery, " / ", len(certs))
	}
	fmt.Println("finished !", numOfQuery)
	wg.Done()
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

		certList = append(certList, *certificate)
	}
	return certList, nil
}
