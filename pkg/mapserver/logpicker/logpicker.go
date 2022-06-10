package logpicker

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	ct "github.com/google/certificate-transparency-go"
	ctTls "github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
	ctX509 "github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/domain"
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

// certResult: Used in worker threads
type certResult struct {
	Err   error
	Certs []*x509.Certificate
}

// GetCertMultiThread fetches certificates from CT log.
// It will download end - start + 1 certificates, starting at start, and finishing with end.
func GetCertMultiThread(ctURL string, startIndex, endIndex, numOfWorker int) (
	[]*x509.Certificate, error) {

	count := endIndex - startIndex + 1
	if count < numOfWorker {
		numOfWorker = count
	}
	if numOfWorker == 0 {
		return nil, nil
	}
	stride := count / numOfWorker
	rem := count % numOfWorker

	resultChan := make(chan certResult)
	for i := 0; i < rem; i++ {
		go workerThread(ctURL, startIndex+i*stride, startIndex+(i+1)*stride, resultChan)
	}
	for i := rem; i < numOfWorker; i++ {
		go workerThread(ctURL, startIndex+i*stride, startIndex+(i+1)*stride-1, resultChan)
	}

	certResult := make([]*x509.Certificate, 0)
	for i := 0; i < numOfWorker; i++ {
		newResult := <-resultChan
		if newResult.Err != nil {
			return nil, fmt.Errorf("UpdateDomainFromLog | %w", newResult.Err)
		}
		certResult = append(certResult, newResult.Certs...)
	}

	close(resultChan)
	return certResult, nil
}

// workerThread: worker thread for log picker
func workerThread(ctURL string, start, end int, resultChan chan certResult) {
	certs, err := getCerts(ctURL, start, end)
	if err != nil {
		resultChan <- certResult{Err: err}
		return
	}
	resultChan <- certResult{Certs: certs}
}

// getCerts gets certificates from CT log. It will request all certs in [start,end] (including both)
func getCerts(ctURL string, start, end int) ([]*ctX509.Certificate, error) {
	allCerts := make([]*ctX509.Certificate, 0, end-start+1)
	for end >= start {
		url := fmt.Sprintf(ctURL+"/ct/v1/get-entries?start=%d&end=%d&quot", start, end)
		resp, err := http.Get(url)
		if err != nil {
			return nil, fmt.Errorf("getCerts | http.Get %w", err)
		}
		newCerts, err := parseCertificatesFromCTLogServerResponse(resp)
		if err != nil {
			return nil, err
		}
		start += len(newCerts)
		allCerts = append(allCerts, newCerts...)
	}
	return allCerts, nil
}

// parseCertificatesFromCTLogServerResponse iteratively gets all requested certificates,
// with as many HTTP requests as necessary.
func parseCertificatesFromCTLogServerResponse(resp *http.Response) ([]*ctX509.Certificate, error) {
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	var ctCerts CertLog
	err := json.Unmarshal(buf.Bytes(), &ctCerts)
	if err != nil {
		return nil, fmt.Errorf("getCerts | json unmarshal %w", err)
	}

	certs := make([]*ctX509.Certificate, len(ctCerts.Entries))
	// parse merkle leaves and append them to the result
	for i, entry := range ctCerts.Entries {
		leafBytes, _ := base64.RawStdEncoding.DecodeString(entry.LeafInput)
		var merkleLeaf ct.MerkleTreeLeaf
		ctTls.Unmarshal(leafBytes, &merkleLeaf)

		var certificate *ctX509.Certificate
		switch entryType := merkleLeaf.TimestampedEntry.EntryType; entryType {
		case ct.X509LogEntryType:
			certificate, err = ctX509.ParseCertificate(merkleLeaf.TimestampedEntry.X509Entry.Data)
			if err != nil {
				return nil, fmt.Errorf("getCerts | ParseCertificate %w", err)
			}
		case ct.PrecertLogEntryType:
			certificate, err = ctX509.ParseTBSCertificate(merkleLeaf.TimestampedEntry.PrecertEntry.TBSCertificate)
			if err != nil {
				return nil, fmt.Errorf("getCerts | ParseTBSCertificate %w", err)
			}
		default:
			return nil, fmt.Errorf("getCerts | CT type unknown %v", entryType)
		}
		certs[i] = certificate
	}
	return certs, nil
}

// GetPCAndRPC: get PC and RPC from url
// TODO(yongzhe): currently just generate random PC and RPC using top 1k domain names
func GetPCAndRPC(ctURL string, startIndex int64, endIndex int64, numOfWorker int) ([]*common.PC, []*common.RPC, error) {
	domainParser, err := domain.NewDomainParser()
	if err != nil {
		return nil, nil, fmt.Errorf("GetPCAndRPC | NewDomainParser | %w", err)
	}
	resultPC := []*common.PC{}
	resultRPC := []*common.RPC{}

	f, err := os.Open(ctURL)
	if err != nil {
		return nil, nil, fmt.Errorf("GetPCAndRPC | os.Open | %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	// read domain names from files
	for scanner.Scan() {
		domainName := scanner.Text()
		// no policy for TLD
		if !domainParser.IsValidDomain(domainName) {
			//fmt.Println("invalid domain name: ", domainName)
			continue
		}
		resultPC = append(resultPC, &common.PC{
			Subject:     domainName,
			TimeStamp:   time.Now(),
			CASignature: generateRandomBytes(),
		})

		resultRPC = append(resultRPC, &common.RPC{
			Subject:   domainName,
			NotBefore: time.Now(),
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("GetPCAndRPC | scanner.Err | %w", err)
	}

	return resultPC, resultRPC, nil
}

func generateRandomBytes() []byte {
	token := make([]byte, 40)
	rand.Read(token)
	return token
}
