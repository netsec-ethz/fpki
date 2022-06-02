package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	ct "github.com/google/certificate-transparency-go"
	ctTls "github.com/google/certificate-transparency-go/tls"
	ctX509 "github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/responder"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
)

var wg sync.WaitGroup

// NOTE: this benchmark should be ran after the updater_benchmark is finished. Because responder needs the updater
func main() {
	db, err := sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/fpki?maxAllowedPacket=1073741824")
	defer db.Close()
	if err != nil {
		panic(err)
	}

	// trancate table
	_, err = db.Exec("TRUNCATE `fpki`.`domainEntries`;")
	if err != nil {
		panic(err)
	}

	// trancate table
	_, err = db.Exec("TRUNCATE `fpki`.`tree`;")
	if err != nil {
		panic(err)
	}

	// trancate table
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

	err = mapUpdater.UpdateFromCT("https://ct.googleapis.com/logs/argon2021", int64(2500000), int64(2509999))
	if err != nil {
		panic(err)
	}

	err = mapUpdater.CommitChanges()
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

	// used for multi-responder fetching; not useful...
	responderGroup := []*responder.MapResponder{}

	// only use one responder
	for i := 0; i < 1; i++ {
		newResponder, err := responder.NewMapResponder(root, 233)
		if err != nil {
			panic(err)
		}
		responderGroup = append(responderGroup, newResponder)
	}

	// collect 10,000 certs, for proof fetching
	collectedCerts := []ctX509.Certificate{}
	for i := 0; i < 500; i++ {
		certList, err := getCerts("https://ct.googleapis.com/logs/argon2021", int64(2500000+i*20), int64(2500000+i*20+19))
		fmt.Println("doanloading : ", int64(2500000+i*20), " - ", int64(2500000+i*20+19))
		if err != nil {
			panic(err)
		}
		for _, cert := range certList {
			collectedCerts = append(collectedCerts, cert)
		}
	}

	fetchStartTime := time.Now()

	wg.Add(1)
	for i := 0; i < 1; i++ {
		ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancelF()

		go worker(collectedCerts[i:], responderGroup[i], ctx)
	}
	wg.Wait()

	fetchEndTime := time.Now()
	fmt.Println("time to fetch "+strconv.Itoa(len(collectedCerts))+" certs: ", fetchEndTime.Sub(fetchStartTime))
}

// collect proof for every domain's Common Name
func worker(certs []ctX509.Certificate, responder *responder.MapResponder, ctx context.Context) {
	domainName := []string{}

	for _, cert := range certs {
		domainName = append(domainName, cert.Subject.CommonName)
	}
	proofMap, err := responder.GetDomainProofs(ctx, domainName)
	if err != nil {
		panic(err)
	}

	for _, proofs := range proofMap {
		fmt.Println("---------------------------")
		isPoP := false
		for _, proof := range proofs {
			if proof.PoI.ProofType == common.PoP {
				isPoP = true
			}
		}
		if !isPoP {
			panic("no PoP")
		}
	}

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
		var merkelLeaf ct.MerkleTreeLeaf
		ctTls.Unmarshal(leafBytes, &merkelLeaf)

		var certificate *ctX509.Certificate
		switch entryType := merkelLeaf.TimestampedEntry.EntryType; entryType {
		case ct.X509LogEntryType:
			certificate, err = ctX509.ParseCertificate(merkelLeaf.TimestampedEntry.X509Entry.Data)
			if err != nil {
				fmt.Println("ERROR: ParseCertificate ", err)
				continue parse_cert_loop
			}
		case ct.PrecertLogEntryType:
			certificate, err = ctX509.ParseTBSCertificate(merkelLeaf.TimestampedEntry.PrecertEntry.TBSCertificate)
			if err != nil {
				fmt.Println("ERROR: ParseTBSCertificate ", err)
				continue parse_cert_loop
			}
		}
		certList = append(certList, *certificate)
	}
	return certList, nil
}
