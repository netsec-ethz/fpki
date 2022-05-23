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

	ct "github.com/google/certificate-transparency-go"
	ctTls "github.com/google/certificate-transparency-go/tls"
	ctX509 "github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/mapserver/responder"
)

var wg sync.WaitGroup

func main() {
	root, err := os.ReadFile("root")
	if err != nil {
		panic(err)
	}

	responderGroup := []*responder.MapResponder{}

	for i := 0; i < 1; i++ {
		newResponder, err := responder.NewMapResponder(root, 233)
		if err != nil {
			panic(err)
		}
		responderGroup = append(responderGroup, newResponder)
	}

	// re-collect the added certs
	collectedCerts := []ctX509.Certificate{}
	for i := 0; i < 500; i++ {
		certList, err := getCerts("https://ct.googleapis.com/logs/argon2021", int64(2500000+i*20), int64(2500000+i*20+19))
		fmt.Println("doanloading : ", int64(1120000+i*20), " - ", int64(1120000+i*20+19))
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
	fmt.Println("time to fetch 10,000 certs: ", fetchEndTime.Sub(fetchStartTime))

}

func worker(certs []ctX509.Certificate, responder *responder.MapResponder, ctx context.Context) {
	start := time.Now()
	for _, cert := range certs {
		_, err := responder.GetDomainProof(ctx, cert.Subject.String())
		if err != nil {
			panic(err)
		}
	}
	end := time.Now()
	fmt.Println("time to do ", len(certs), " :", end.Sub(start))
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
