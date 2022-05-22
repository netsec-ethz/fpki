package logpicker

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	ct "github.com/google/certificate-transparency-go"
	ctTls "github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
	ctX509 "github.com/google/certificate-transparency-go/x509"
)

// CertData: data structure of leaf from CT log
type CertData struct {
	LeafInput string `json:"leaf_input"`
	ExtraData string `json:"extra_data"`
}

// CertLog: Data from CT log
type CertLog struct {
	Entries []CertData
}

type CertResult struct {
	Err   error
	Certs []*x509.Certificate
}

// TODO(yongzhe): modify the error handling
// UpdateDomainFromLog: Fetch certificates from log,
func GetCertMultiThread(ctURL string, startIndex int64, endIndex int64, numOfWorker int) ([]*x509.Certificate, int, error) {
	gap := (endIndex - startIndex) / int64(numOfWorker)
	resultChan := make(chan CertResult)
	for i := 0; i < numOfWorker-1; i++ {
		go workerThread(ctURL, startIndex+int64(i)*gap, startIndex+int64(i+1)*gap-1, resultChan)
	}
	// last work take charge of the rest of the queries
	// Because var "gap" might be rounded.
	go workerThread(ctURL, startIndex+int64(numOfWorker-1)*gap, endIndex, resultChan)

	certResult := []*x509.Certificate{}
	for i := 0; i < numOfWorker; i++ {
		newResult := <-resultChan
		if newResult.Err != nil {
			return nil, 0, fmt.Errorf("UpdateDomainFromLog | %w", newResult.Err)
		}
		certResult = append(certResult, newResult.Certs...)
	}

	close(resultChan)
	return certResult, len(certResult), nil
}

// workerThread: worker thread for log picker
func workerThread(ctURL string, start, end int64, resultChan chan CertResult) {
	var certs []*x509.Certificate
	for i := start; i < end; i += 20 {
		var newCerts []*x509.Certificate
		var err error
		// TODO(yongzhe): better error handling; retry if error happens
		if end-i > 20 {
			newCerts, err = getCerts(ctURL, i, i+19)
			if err != nil {
				resultChan <- CertResult{Err: err}
				continue
			}
		} else {
			newCerts, err = getCerts(ctURL, i, i+end-i)
			if err != nil {
				resultChan <- CertResult{Err: err}
				continue
			}
		}
		certs = append(certs, newCerts...)
	}
	resultChan <- CertResult{Certs: certs}
}

// get certificate from CT log
func getCerts(ctURL string, start int64, end int64) ([]*ctX509.Certificate, error) {
	url := fmt.Sprintf(ctURL+"/ct/v1/get-entries?start=%d&end=%d&quot", start, end)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("http.Get %w", err)
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)

	var resultsCerLog CertLog
	json.Unmarshal(buf.Bytes(), &resultsCerLog)

	certList := []*ctX509.Certificate{}

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
		certList = append(certList, certificate)
	}

	return certList, nil
}
