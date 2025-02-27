package logfetcher

import (
	"context"
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/util"
)

const (
	NumFileReaders = 8
	NumParsers     = 64
)

const (
	CertificateColumn = 3
	CertChainColumn   = 4
)

// LocalLogFetcher is used to fetch CT TBS certificates from locally stored (gzipped) csv files
// containing the certificate, its certificate chain, and certain values such as the expiration time
// for quick expiration checks.
type LocalLogFetcher struct {
	url    string
	folder string
	start  int64 // TODO(juagargi) start & end should go into fetch() and not as part as the type.
	end    int64

	// timestamp used to decide whether certificates are expired or not
	now time.Time

	// finding csv files
	achievableStateMap map[int64][]*CsvFileInfo

	// reading cvs files
	certWithChainChan chan *CertWithChainData
	incomingFileCh    chan util.CsvFile // New files with certificates to be ingested
	errorCh           chan error        // Errors accumulate here

	processBatchSize int64 // We unblock NextBatch in batches of this size.

	// This variable restricts the number of batches that are processed per log fetcher by limiting
	// the maximum number of csv rows (note that this limit may be exceeded since at least a single
	// batch must be processed)
	maxIngestionSize uint64

	chanResults chan *result
	stopping    bool // Set to request the LogFetcher to stop fetching.

	inputFiles []*CsvFileInfo

	// The chanResults channel is used to obtain results from this fetcher. Each call to NextBatch
	// pulls one full result from the channel into the currentResult variable. And each call
	// to ReturnNextBatch returns it.
	currentResult *result // The last result from the batch.
}

var _ Fetcher = (*LocalLogFetcher)(nil)

type CertWithChainData struct {
	CertID        *common.SHA256Output   // The ID (the SHA256) of the certificate.
	Cert          ctx509.Certificate     // The payload of the certificate.
	ChainIDs      []*common.SHA256Output // The trust chain of the certificate.
	ChainPayloads []*ctx509.Certificate  // The payloads of the chain. Is nil if already cached.
	Expired       bool
}

type CsvFileInfo struct {
	path      string
	isGzipped bool
	start     int64
	end       int64
}

func NewLocalLogFetcher(url, folder string, csvIngestionMaxRows uint64) (*LocalLogFetcher, error) {
	fetcher := &LocalLogFetcher{
		url:    url,
		folder: folder,

		processBatchSize: defaultProcessBatchSize,
		maxIngestionSize: csvIngestionMaxRows,
	}
	return fetcher, nil
}

func (f *LocalLogFetcher) Initialize(updateStartTime time.Time) error {
	// reset current time for removing expired certificates
	f.now = updateStartTime

	// reset values
	f.chanResults = make(chan *result, preloadCount)
	f.incomingFileCh = make(chan util.CsvFile)
	f.certWithChainChan = make(chan *CertWithChainData)
	f.errorCh = make(chan error)

	// find all csv files
	gzFiles, csvFiles, err := listFiles(f.folder)
	if err != nil {
		return err
	}
	f.inputFiles = append(gzFiles, csvFiles...)

	// combine files into continuous index ranges starting with simple ranges consisting of a single
	// file
	f.achievableStateMap = map[int64][]*CsvFileInfo{}
	for _, fileInfo := range f.inputFiles {
		if _, ok := f.achievableStateMap[fileInfo.start]; ok {
			return fmt.Errorf("gzip file starts are not unique: %s vs %s\n", fileInfo.path, f.achievableStateMap[fileInfo.start][0].path)
		}
		f.achievableStateMap[fileInfo.start] = []*CsvFileInfo{fileInfo}
	}

	// recursively find all file chains for the largest possible range
	for start := range f.achievableStateMap {
		f.achievableStateMap[start] = getGzFileChain(f.achievableStateMap, start)
	}

	f.processIncomingFiles()
	return nil
}

func (f *LocalLogFetcher) URL() string {
	return f.url
}

func (fi *CsvFileInfo) String() string {
	return filepath.Base(fi.path)
}

func (f *LocalLogFetcher) GetCurrentState(ctx context.Context, lastState State) (State, error) {
	// return max achievable state
	if entries, ok := f.achievableStateMap[int64(lastState.Size)]; ok {
		// find targetSize of rows from N >= 1 csv files such that targetSize-currentSize <= MaxIngestionSize
		var targetSize uint64
		for i, entry := range entries {
			// always process at least one entry
			if i > 0 && entry.end-int64(lastState.Size)+1 > int64(f.maxIngestionSize) {
				break
			}
			targetSize = uint64(entry.end) + 1
		}
		return State{
			Size: targetSize,
			STH:  nil,
		}, nil
	} else {
		fmt.Printf("No subsequent local certificates available at %d\n", int64(lastState.Size))
		return lastState, nil
	}
}

// StartFetching will start fetching certificates in the background, so that there is
// at most two batches ready to be immediately read by NextBatch.
func (f *LocalLogFetcher) StartFetching(start, end int64) {
	f.start = start
	f.end = end
	requestedFiles := []*CsvFileInfo{}
	for _, entry := range f.achievableStateMap[start] {
		if entry.end > end {
			break
		}
		requestedFiles = append(requestedFiles, entry)
	}
	if len(f.achievableStateMap[start]) == 0 {
		fmt.Printf("No new files in local certificate folder for %s starting at index %d\n", f.URL(), start)
	} else {
		remaining := "\n"
		if len(requestedFiles) < len(f.achievableStateMap[start]) {
			remaining = fmt.Sprintf(" (%d files remaining [%d, %d])\n", len(f.achievableStateMap[start])-len(requestedFiles), end+1, f.achievableStateMap[start][len(f.achievableStateMap[start])-1].end)
		}
		fmt.Printf("Start fetching from local certificate folder for %s in range [%d, %d] (%d files) %s", f.URL(), start, end, len(requestedFiles), remaining)
	}

	// process the requested files in a separate go routine
	go func() {
		for _, entry := range requestedFiles {
			fmt.Printf("Processing Certificate File %s\n", entry)
			if entry.isGzipped {
				f.addGzFiles([]string{entry.path})
			} else {
				f.addCsvFiles([]string{entry.path})
			}
		}
		close(f.incomingFileCh)
	}()
}

func (f *LocalLogFetcher) StopFetching() {
	// TODO: abort csv fetching/parsing if this value is set to true
	f.stopping = true
}

// NextBatch returns true if there is a next batch to be retrieved or false if no further batches
// can be retrieved for this CT log
func (f *LocalLogFetcher) NextBatch(ctx context.Context) bool {
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
				len(f.currentResult.chains) == 0 &&
				f.currentResult.expired == 0 {
			// If no  error and no data, return false
			return false // do not attempt to get result
		}
	}
	return true
}

// ReturnNextBatch returns the next batch of certificates as if it were a channel.
// The call blocks until a whole batch is available. The last batch may have less elements.
// Returns nil when there is no more batches, i.e. all certificates have been fetched.
func (f *LocalLogFetcher) ReturnNextBatch() (
	certs []ctx509.Certificate,
	chains [][]*ctx509.Certificate,
	excluded int,
	err error) {
	return f.currentResult.certs, f.currentResult.chains, f.currentResult.expired, f.currentResult.err
}

// AddGzFiles adds a CSV .gz file to the initial stage.
// It blocks until it is accepted.
func (p *LocalLogFetcher) addGzFiles(fileNames []string) {
	for _, filename := range fileNames {
		p.incomingFileCh <- (&util.GzFile{}).WithFile(filename)
	}
}

// AddGzFiles adds a .csv file to the initial stage.
// It blocks until it is accepted.
func (p *LocalLogFetcher) addCsvFiles(fileNames []string) {
	for _, filename := range fileNames {
		p.incomingFileCh <- (&util.UncompressedFile{}).WithFile(filename)
	}
}

// processFile processes any File.
// This stage is responsible of parsing the data into X509 certificates and chains.
func (p *LocalLogFetcher) processFile(f util.CsvFile) {
	r, err := f.Open()
	if err != nil {
		p.errorCh <- err
		return
	}
	// ingestWithCSV will send data to the cert with chain channel
	if err := p.ingestWithCSV(r); err != nil {
		p.errorCh <- err
		return
	}
	if err := f.Close(); err != nil {
		p.errorCh <- err
		return
	}
}

// ingestWithCSV spawns as many goroutines as specified by the constant `NumParsers`,
// that divide the CSV rows and parse them.
// For efficiency reasons, the whole file is read at once in memory, and its rows divided
// from there.
func (p *LocalLogFetcher) ingestWithCSV(fileReader io.Reader) error {
	reader := csv.NewReader(fileReader)
	reader.FieldsPerRecord = -1 // don't check number of fields

	parseFunction := func(fields []string, lineNo int) error {
		// First avoid even parsing already expired certs.
		n, err := getExpiration(fields)
		if err != nil {
			return err
		}
		if p.now.After(time.Unix(n, 0)) {
			// Skip this certificate.
			p.certWithChainChan <- &CertWithChainData{
				Expired: true,
			}
			return nil
		}

		// From this point on, we need to parse the certificate.
		rawBytes, err := base64.StdEncoding.DecodeString(fields[CertificateColumn])
		if err != nil {
			return err
		}
		certID := common.SHA256Hash32Bytes(rawBytes)
		cert, err := ctx509.ParseCertificate(rawBytes)
		if err != nil {
			return err
		}

		if p.now.After(cert.NotAfter) {
			// Skip this certificate.
			p.certWithChainChan <- &CertWithChainData{
				Expired: true,
			}
			return nil
		}

		// The certificate chain is a list of base64 strings separated by semicolon (;).
		strs := strings.Split(fields[CertChainColumn], ";")
		chain := make([]*ctx509.Certificate, len(strs))
		chainIDs := make([]*common.SHA256Output, len(strs))
		for i, s := range strs {
			rawBytes, err = base64.StdEncoding.DecodeString(s)
			if err != nil {
				return fmt.Errorf("at line %d: %s\n%s", lineNo, err, fields[CertChainColumn])
			}
			// Check if the parent certificate is in the cache.
			id := common.SHA256Hash32Bytes(rawBytes)
			// Not seen before, push it to the DB.
			chain[i], err = ctx509.ParseCertificate(rawBytes)
			if err != nil {
				return fmt.Errorf("at line %d: %s\n%s", lineNo, err, fields[CertChainColumn])
			}
			chainIDs[i] = &id
		}
		p.certWithChainChan <- &CertWithChainData{
			Cert:          *cert,
			CertID:        &certID,
			ChainPayloads: chain,
			ChainIDs:      chainIDs,
		}
		return nil
	}

	type lineAndFields struct {
		lineNo int
		fields []string
	}
	recordsChan := make(chan *lineAndFields)

	wg := sync.WaitGroup{}
	wg.Add(NumParsers)
	for r := 0; r < NumParsers; r++ {
		go func() {
			defer wg.Done()
			for x := range recordsChan {
				if err := parseFunction(x.fields, x.lineNo); err != nil {
					panic(err)
				}
			}
		}()
	}
	records, err := reader.ReadAll()
	if err != nil {
		return err
	}
	for lineNo, fields := range records {
		if len(fields) == 0 { // there exist empty lines (e.g. at the end of the gz files)
			continue
		}
		recordsChan <- &lineAndFields{
			lineNo: lineNo,
			fields: fields,
		}
	}
	close(recordsChan)
	wg.Wait()
	return nil
}

// getExpiration returns the expiration time in seconds. It is stored already in seconds on the
// last column of the CSV entry, usually index 7.
func getExpiration(fields []string) (int64, error) {
	// Because some entries in the CSVs are malformed by not escaping their SAN field, we cannot
	// reliably use a column index, but the last column of the entry.
	expirationColumn := len(fields) - 1

	s := strings.Split(fields[expirationColumn], ".")
	if len(s) != 2 {
		return 0, fmt.Errorf("unrecognized timestamp in the last column: %s", fields[expirationColumn])
	}
	exp, err := strconv.ParseInt(s[0], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parsing the expiration time \"%s\" got: %w",
			fields[expirationColumn], err)
	}
	return exp, nil
}

func (l *LocalLogFetcher) processIncomingFiles() {
	// Process files and parse the CSV contents:
	go func() {
		// Spawn a fixed number of file readers.
		wg := sync.WaitGroup{}
		wg.Add(NumFileReaders)
		for r := 0; r < NumFileReaders; r++ {
			go func() {
				defer wg.Done()
				for f := range l.incomingFileCh {
					l.processFile(f)
				}
			}()
		}
		wg.Wait()
		fmt.Println()
		fmt.Println("Done with incoming files, closing parsed data channel.")
		// Because we are done writing parsed content, close this stage's output channel:
		close(l.certWithChainChan)
	}()

	// Process the parsed content into the DB, and from DB into SMT:
	go func() {
		var currentSize int64 = 0
		var r *result = &result{}
		for data := range l.certWithChainChan {
			currentSize += 1
			if data.Expired {
				r.expired += 1
			} else {
				r.certs = append(r.certs, data.Cert)
				r.chains = append(r.chains, data.ChainPayloads)
			}
			if currentSize >= l.processBatchSize {
				l.chanResults <- r
				currentSize = 0
				r = &result{}
			}
		}
		if currentSize > 0 {
			l.chanResults <- r
			currentSize = 0
			r = &result{}
		}
		close(l.chanResults)

		// There is no more processing to do, close the errors channel and allow the
		// error processor to finish.
		close(l.errorCh)
	}()

	go func() {
		// Print errors and return error if there was any error printed:
		l.processErrorChannel()
	}()
}

// processErrorChannel outputs the errors it encounters in the errors channel.
// Returns with error if any is found, or nil if no error.
func (p *LocalLogFetcher) processErrorChannel() error {
	var errorsFound bool
	for err := range p.errorCh {
		if err == nil {
			continue
		}
		errorsFound = true
		fmt.Fprintf(os.Stderr, "%s\n", err)
	}
	if errorsFound {
		return fmt.Errorf("errors found while processing. See above")
	}
	return nil
}

func getGzFileChain(stateMap map[int64][]*CsvFileInfo, start int64) []*CsvFileInfo {
	entry, ok := stateMap[start]
	if !ok {
		return nil
	}
	nextStart := entry[len(entry)-1].end + 1
	return append(entry, getGzFileChain(stateMap, nextStart)...)
}

// getFileInfo extracts the index range and whether the file is gzipped into a struct
func getFileInfo(path, fileName string, isGzipped bool) (*CsvFileInfo, error) {
	extension := ".csv"
	if isGzipped {
		extension = ".gz"
	}
	if r, ok := strings.CutSuffix(fileName, extension); ok {
		rValues := strings.Split(r, "-")
		if len(rValues) == 2 {
			start, err := strconv.ParseInt(rValues[0], 10, 64)
			if err != nil {
				return nil, err
			}
			end, err := strconv.ParseInt(rValues[1], 10, 64)
			if err != nil {
				return nil, err
			}
			return &CsvFileInfo{
				path:      path,
				isGzipped: isGzipped,
				start:     start,
				end:       end,
			}, nil
		}
	}
	return nil, nil
}

// listFiles recursively finds all .csv and .gz files located in the given folder (or any subfolder)
func listFiles(dir string) (gzFiles, csvFiles []*CsvFileInfo, err error) {
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if !d.IsDir() {
			gzFile, err := getFileInfo(path, d.Name(), true)
			if err != nil {
				return err
			}
			if gzFile != nil {
				gzFiles = append(gzFiles, gzFile)
			}
			csvFile, err := getFileInfo(path, d.Name(), false)
			if err != nil {
				return err
			}
			if csvFile != nil {
				csvFiles = append(csvFiles, csvFile)
			}
		}
		return nil
	})
	return
}
