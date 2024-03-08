package logfetcher

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	ctx509 "github.com/google/certificate-transparency-go/x509"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/domain"
)

const defaultServerBatchSize = 128
const defaultProcessBatchSize = defaultServerBatchSize * 128

const preloadCount = 2 // Number of batches the LogFetcher tries to preload.

type Fetcher interface {
	URL() string
	GetCurrentState(ctx context.Context) (State, error)
	StartFetching(startIndex, endIndex int64)
	StopFetching()

	// Like with sql.Rows.Next()
	NextBatch(ctx context.Context) bool
	// Like sql.Rows.Scan(...)
	ReturnNextBatch() ([]*ctx509.Certificate, [][]*ctx509.Certificate, error)
}

type State struct {
	Size uint64
	// STH is the signed tree head of the server.
	STH []byte
}

// LogFetcher is used to download CT TBS certificates. It has state and keeps some routines
// downloading certificates in the background, trying to prefetch preloadCount batches.
// LogFetcher uses the certificate-transparency-go/client from google to do the heavy lifting.
// The default size of the server side batch is 128, i.e. the server expects queries in blocks
// of 128 entries.
// TODO(juagargi) Use lists of CT log servers: check certificate-transparency-go/ctutil/sctcheck
// or ct/client/ctclient for a full and standard list that may already implement this.
type LogFetcher struct {
	url   string
	start int64 // TODO(juagargi) start & end should go into fetch() and not as part as the type.
	end   int64

	serverBatchSize  int64 // The server requires queries in blocks of this size.
	processBatchSize int64 // We unblock NextBatch in batches of this size.
	ctClient         *client.LogClient
	chanResults      chan *result
	stopping         bool // Set to request the LogFetcher to stop fetching.

	// The chanResults channel is used to obtain results from this fetcher. Each call to NextBatch
	// pulls one full result from the channel into the currentResult variable. And each call
	// to GetBatchResults returns it.
	currentResult *result // The last result from the batch.
}

type result struct {
	certs  []*ctx509.Certificate
	chains [][]*ctx509.Certificate
	err    error
}

func NewLogFetcher(url string) (*LogFetcher, error) {
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConnsPerHost:   10,
			DisableKeepAlives:     false,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	opts := jsonclient.Options{UserAgent: "ct-go-ctclient/1.0"}
	ctClient, err := client.New(url, httpClient, opts)
	if err != nil {
		return nil, err
	}
	return &LogFetcher{
		url: url,

		serverBatchSize:  defaultServerBatchSize,
		processBatchSize: defaultProcessBatchSize,
		ctClient:         ctClient,
		chanResults:      nil,
	}, nil
}

func (f LogFetcher) URL() string {
	return f.url
}

func (f LogFetcher) GetCurrentState(ctx context.Context) (State, error) {
	sth, err := f.ctClient.GetSTH(ctx)
	if err != nil {
		return State{}, err
	}
	return State{
		Size: sth.TreeSize,
		// TODO(juagargi) this STH will probably need the whole SignedTreeHead structure,
		// not just the signature.
		STH: sth.TreeHeadSignature.Signature,
	}, nil
}

// StartFetching will start fetching certificates in the background, so that there is
// at most two batches ready to be immediately read by NextBatch.
func (f *LogFetcher) StartFetching(start, end int64) {
	f.chanResults = make(chan *result, preloadCount)
	f.start = start
	f.end = end
	go f.fetch()
}

func (f *LogFetcher) StopFetching() {
	f.stopping = true
}

// NextBatch returns true if there is a next batch to be retrieved, or error, I.e. if the call to
// ReturnNextBatch will return something other than nil, nil, nil.
func (f *LogFetcher) NextBatch(ctx context.Context) bool {
	f.currentResult = &result{}
	var ok bool
	select {
	case <-ctx.Done():
		f.currentResult.err = ctx.Err()
	case f.currentResult, ok = <-f.chanResults:
		// Only in case that there is no error AND no data should we return false:
		if !ok ||
			f.currentResult.err == nil &&
				len(f.currentResult.certs) == 0 &&
				len(f.currentResult.chains) == 0 {
			// If no  error and no data, return false
			return false // do not attempt to get result
		}
	}
	return true
}

// ReturnNextBatch returns the next batch of certificates as if it were a channel.
// The call blocks until a whole batch is available. The last batch may have less elements.
// Returns nil when there is no more batches, i.e. all certificates have been fetched.
func (f *LogFetcher) ReturnNextBatch() (
	certs []*ctx509.Certificate,
	chains [][]*ctx509.Certificate,
	err error) {

	return f.currentResult.certs, f.currentResult.chains, f.currentResult.err
}

// FetchAllCertificates will block until all certificates and chains [start,end] have been fetched.
func (f *LogFetcher) FetchAllCertificates(
	ctx context.Context,
	start,
	end int64,
) (
	certs []*ctx509.Certificate,
	chains [][]*ctx509.Certificate,
	err error,
) {

	f.StartFetching(start, end)
	certs = make([]*ctx509.Certificate, 0, end-start+1)
	chains = make([][]*ctx509.Certificate, 0, end-start+1)
	for f.NextBatch(ctx) {
		bCerts, bChains, bErr := f.ReturnNextBatch()
		if bErr != nil {
			err = bErr
			return
		}
		if len(bCerts) == 0 {
			break
		}
		certs = append(certs, bCerts...)
		chains = append(chains, bChains...)
	}
	f.StopFetching()
	return
}

func (f *LogFetcher) fetch() {
	defer close(f.chanResults)

	if f.start > f.end {
		return
	}
	// Taking into account the batchSize, compute the # of calls to getEntriesInBatches.
	// It calls count-1 times with the batchSize, and 1 time with the remainder.
	count := 1 + (f.end-f.start)/f.processBatchSize

	leafEntries := make([]*ct.LeafEntry, f.processBatchSize)
	for i := int64(0); i < count; i++ {
		start := f.start + i*f.processBatchSize
		end := min(f.end, start+f.processBatchSize-1)
		n, err := f.getRawEntriesInBatches(leafEntries, start, end)
		if err != nil {
			f.chanResults <- &result{
				err: err,
			}
			return // Don't continue processing when errors.
		}
		if f.stopping {
			f.stopping = false // We are handling the stop now.
			return
		}
		certEntries := make([]*ctx509.Certificate, n)
		chainEntries := make([][]*ctx509.Certificate, n)
		// Parse each entry to certificates and chains.
		for i, leaf := range leafEntries[:n] {
			index := start + int64(i)
			raw, err := ct.RawLogEntryFromLeaf(index, leaf)
			if err != nil {
				f.chanResults <- &result{
					err: err,
				}
				return
			}
			// Certificate.
			cert, err := ctx509.ParseCertificate(raw.Cert.Data)
			if ctx509.IsFatal(err) {
				f.chanResults <- &result{
					err: err,
				}
				return
			}
			certEntries[i] = cert
			// Chain.
			chainEntries[i] = make([]*ctx509.Certificate, len(raw.Chain))
			for j, c := range raw.Chain {
				chainEntries[i][j], err = ctx509.ParseCertificate(c.Data)
				if err != nil {
					f.chanResults <- &result{
						err: err,
					}
					return
				}
			}
		}
		// Send the result.
		f.chanResults <- &result{
			certs:  certEntries,
			chains: chainEntries,
		}
	}
}

// streamRawEntries fetches certificates from CT log using getCerts.
// streamRawEntries repeats a call to getCerts as many times as necessary in batches of
// serverBatchSize.
// streamRawEntries will download end - start + 1 certificates,
// starting at start, and finishing with end.
func (f *LogFetcher) getRawEntriesInBatches(leafEntries []*ct.LeafEntry, start, end int64) (
	int64, error) {

	assert(end >= start, "logic error: call to getRawEntriesInBatches with %d and %d", start, end)
	_ = leafEntries[end-start] // Fail early if wrong size.

	// TODO(juagargi) should we align the calls to serverBatchSize
	batchCount := (end - start + 1) / f.serverBatchSize

	if f.stopping {
		return 0, nil
	}
	// Do batches.
	for i := int64(0); i < batchCount; i++ {
		bStart := start + i*f.serverBatchSize
		bEnd := bStart + f.serverBatchSize - 1
		entries := leafEntries[i*f.serverBatchSize : (i+1)*f.serverBatchSize]

		n, err := f.getRawEntries(entries, bStart, bEnd)
		if err != nil {
			return i * f.serverBatchSize, err
		}
		if f.stopping {
			return i*f.serverBatchSize + n, nil
		}
		assert(n == f.serverBatchSize, "bad size in getRawEntriesInBatches")
	}

	// Do remainder of batches.
	remStart := batchCount*f.serverBatchSize + start
	remEnd := end
	if remEnd >= remStart {
		// There is a remainder todo.
		entries := leafEntries[batchCount*f.serverBatchSize : end-start+1]
		n, err := f.getRawEntries(entries, remStart, remEnd)
		if err != nil {
			return batchCount * f.serverBatchSize, err
		}
		if f.stopping {
			return remStart + n, nil
		}
		assert(n == remEnd-remStart+1, "bad remainder size in getRawEntriesInBatches")
	}

	return end - start + 1, nil
}

// getRawEntries downloads raw entries. It doesn't have a concept of batch size, and  will
// re-query the server if it didn't return as many entries as requested.
// The function returns all entries [start,end], both inclusive.
// It returns the number of retrieved entries, plus maybe an error.
// The rawEntries must be at least of size end-start+1, or panic.
func (f *LogFetcher) getRawEntries(
	leafEntries []*ct.LeafEntry,
	start,
	end int64,
) (int64, error) {

	_ = leafEntries[end-start] // Fail early if the slice is too small.

	for offset := int64(0); offset < end-start+1; {
		if f.stopping {
			// Requested to stop
			return 0, nil
		}
		rsp, err := f.ctClient.GetRawEntries(context.Background(), start+offset, end)
		if err != nil {
			return offset, err
		}
		for i := int64(0); i < int64(len(rsp.Entries)); i++ {
			e := rsp.Entries[i]
			leafEntries[offset+i] = &e
		}
		offset += int64(len(rsp.Entries))
	}
	return end - start + 1, nil
}

// GetPCAndRPCs: get PC and RPC from url
// TODO(yongzhe): currently just generate random PC and RPC using top 1k domain names
func GetPCAndRPCs(
	ctURL string,
	startIndex int64,
	endIndex int64,
	numOfWorker int,
) ([]*common.PolicyCertificate, error) {

	resultPolCerts := make([]*common.PolicyCertificate, 0)

	f, err := os.Open(ctURL)
	if err != nil {
		return nil, fmt.Errorf("GetPCAndRPC | os.Open | %w", err)
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

		resultPolCerts = append(resultPolCerts, common.NewPolicyCertificate(
			0,
			0, // serial number
			domainName,
			time.Now(),                       // not before
			time.Now().Add(time.Microsecond), // not after
			false,                            // can issue
			false,                            // can own
			generateRandomBytes(),            // public key
			common.RSA,
			common.SHA256,
			time.Now(),                // timestamp
			common.PolicyAttributes{}, // policy attributes
			nil,                       // owner signature
			nil,                       // owner hash
			nil,                       // server timestamps
			nil,                       // issuer signature
			nil,                       // issuer hash
		))
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("GetPCAndRPC | scanner.Err | %w", err)
	}

	return resultPolCerts, nil
}

func generateRandomBytes() []byte {
	token := make([]byte, 40)
	rand.Read(token)
	return token
}

func min(a, b int64) int64 {
	if b < a {
		return b
	}
	return a
}

func assert(cond bool, format string, params ...any) {
	if !cond {
		panic(fmt.Errorf(format, params...))
	}
}
