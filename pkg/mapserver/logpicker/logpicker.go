package logpicker

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"
	ctTls "github.com/google/certificate-transparency-go/tls"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/domain"
)

// LogFetcher is used to download batches of certificates. It has state and keeps some routines
// downloading certificates in the background, trying to prefetch the next two batches.
// By default it uses 16 workers, and batches of size 1K.
type LogFetcher struct {
	URL         string
	Start       int
	End         int
	WorkerCount int
	BatchSize   int
	resultChan  chan []*ctx509.Certificate // batches of certificates
	errChan     chan error
	stopChan    chan struct{} // tells the workers to stop fetching
}

// StartFetching will start fetching certificates in the background, so that there is
// at most two batches ready to be immediately read by NextBatch.
func (f *LogFetcher) StartFetching() {
	if f.BatchSize == 0 {
		f.BatchSize = 1000
	}
	if f.WorkerCount == 0 {
		f.WorkerCount = 16
	}
	f.resultChan = make(chan []*ctx509.Certificate, 2)
	f.errChan = make(chan error)
	f.stopChan = make(chan struct{})
	go f.fetch()
}

func (f *LogFetcher) StopFetching() {
	f.stopChan <- struct{}{}
}

// NextBatch returns the next batch of certificates as if it were a channel.
// The call blocks until a whole batch is available. The last batch may have less elements.
// Returns nil when there is no more batches, i.e. all certificates have been fetched.
func (f *LogFetcher) NextBatch(ctx context.Context) ([]*ctx509.Certificate, error) {
	select {
	case <-ctx.Done():
		f.StopFetching()
		return nil, fmt.Errorf("NextBatch %w", ctx.Err())
	case certs := <-f.resultChan:
		return certs, nil
	case err := <-f.errChan:
		return nil, err
	}
}

// FetchAllCertificates will block until all certificates [start,end] have been fetched.
func (f *LogFetcher) FetchAllCertificates(ctx context.Context) ([]*ctx509.Certificate, error) {
	f.StartFetching()
	certs := make([]*ctx509.Certificate, 0, f.End-f.Start+1)
	for {
		batch, err := f.NextBatch(ctx)
		if err != nil {
			return nil, err
		}
		if len(batch) == 0 {
			break
		}
		certs = append(certs, batch...)
	}
	return certs, nil
}

func (f *LogFetcher) fetch() {
	for start, end := f.Start, min(f.End, f.Start+f.BatchSize-1); start <= f.End; start, end =
		start+f.BatchSize, min(end+f.BatchSize, f.End) {

		certs, err := getCertificates(f.URL, start, end, f.WorkerCount, f.stopChan)
		if err != nil {
			f.errChan <- err
			return
		}
		f.resultChan <- certs
	}
	close(f.errChan)
	close(f.resultChan)
	close(f.stopChan)
}

// getCertificates fetches certificates from CT log.
// It will download end - start + 1 certificates, starting at start, and finishing with end.
func getCertificates(ctURL string, startIndex, endIndex, numOfWorker int, stopChan chan struct{}) (
	[]*ctx509.Certificate, error) {

	count := endIndex - startIndex + 1
	if count < numOfWorker {
		numOfWorker = count
	}
	if numOfWorker == 0 {
		return nil, nil
	}

	certsCol := make([][]*ctx509.Certificate, numOfWorker)
	errs := make([]error, numOfWorker)
	wg := sync.WaitGroup{}
	wg.Add(numOfWorker)

	stride := count / numOfWorker
	rem := count % numOfWorker

	for i := 0; i < rem; i++ {
		go func(start, end int, certsPtr *[]*ctx509.Certificate, errPtr *error) {
			defer wg.Done()
			*certsPtr, *errPtr = getCerts(ctURL, start, end, stopChan)
		}(startIndex+i*stride, startIndex+(i+1)*stride, &certsCol[i], &errs[i])
	}
	for i := rem; i < numOfWorker; i++ {
		go func(start, end int, certsPtr *[]*ctx509.Certificate, errPtr *error) {
			defer wg.Done()
			*certsPtr, *errPtr = getCerts(ctURL, start, end, stopChan)
		}(startIndex+i*stride, startIndex+(i+1)*stride-1, &certsCol[i], &errs[i])
	}

	certs := make([]*ctx509.Certificate, 0, count)
	wg.Wait()
	for i := 0; i < numOfWorker; i++ {
		if errs[i] != nil {
			return nil, errs[i]
		}
		certs = append(certs, certsCol[i]...)
	}
	return certs, nil
}

// getCerts gets certificates from CT log. It will request all certs in [start,end] (including both)
func getCerts(ctURL string, start, end int, stopChan chan struct{}) ([]*ctx509.Certificate, error) {
	allCerts := make([]*ctx509.Certificate, 0, end-start+1)
	for end >= start {
		url := fmt.Sprintf(ctURL+"/ct/v1/get-entries?start=%d&end=%d&quot", start, end)
		resp, err := http.Get(url)
		if err != nil {
			return nil, fmt.Errorf("getCerts | http.Get %w", err)
		}
		select {
		case <-stopChan: // requested to stop
			return nil, nil
		default:
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
func parseCertificatesFromCTLogServerResponse(resp *http.Response) ([]*ctx509.Certificate, error) {
	type CertLog struct {
		Entries []struct {
			LeafInput string `json:"leaf_input"`
			ExtraData string `json:"extra_data"`
		}
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	var ctCerts CertLog
	err := json.Unmarshal(buf.Bytes(), &ctCerts)
	if err != nil {
		return nil, fmt.Errorf("getCerts | json unmarshal %w\n%s", err, buf.String())
	}

	certs := make([]*ctx509.Certificate, len(ctCerts.Entries))
	// parse merkle leaves and append them to the result
	for i, entry := range ctCerts.Entries {
		leafBytes, _ := base64.RawStdEncoding.DecodeString(entry.LeafInput)
		var merkleLeaf ct.MerkleTreeLeaf
		ctTls.Unmarshal(leafBytes, &merkleLeaf)

		var certificate *ctx509.Certificate
		switch entryType := merkleLeaf.TimestampedEntry.EntryType; entryType {
		case ct.X509LogEntryType:
			certificate, err = ctx509.ParseCertificate(merkleLeaf.TimestampedEntry.X509Entry.Data)
			if err != nil {
				return nil, fmt.Errorf("getCerts | ParseCertificate %w", err)
			}
		case ct.PrecertLogEntryType:
			certificate, err = ctx509.ParseTBSCertificate(merkleLeaf.TimestampedEntry.PrecertEntry.TBSCertificate)
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
		if !domain.IsValidDomain(domainName) {
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

func min(a, b int) int {
	if b < a {
		return b
	}
	return a
}
