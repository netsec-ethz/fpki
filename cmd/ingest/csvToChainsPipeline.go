package main

import (
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	ctx509 "github.com/google/certificate-transparency-go/x509"

	"github.com/netsec-ethz/fpki/cmd/ingest/cache"
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	"github.com/netsec-ethz/fpki/pkg/util"
)

type CsvToChainsPipeline struct {
	IncomingChan  chan util.CsvFile               // New files with certificates to be ingested
	NextStageChan *chan updater.CertWithChainData // Should be readied by the next stage.

	nextStage  *ChainsToCertificatesPipeline
	now        time.Time
	numReaders int // Number of file readers
	numParsers int // Number of CSV parsers (once in memory).
	stats      *updater.Stats
	presence   cache.Cache // IDs of certificates already seen

	errChan chan error
}

// NewCsvToChainsPipeline
// The NextStageChan has to be prepared by the next stage and set here prior to Resume().
func NewCsvToChainsPipeline() *CsvToChainsPipeline {
	return &CsvToChainsPipeline{

		now:      time.Now(),
		presence: cache.NewPresenceCache(LruCacheSize),
	}
}

func (p *CsvToChainsPipeline) Resume() {
	p.nextStage.Resume()
	p.resume()
}

func (p *CsvToChainsPipeline) Wait() error {
	// Wait needs to check if there were errors in this or the next stage.
	errors := make([]error, 2)
	wg := sync.WaitGroup{}
	wg.Add(len(errors))

	// This stage status.
	go func() {
		defer wg.Done()
		errors[0] = <-p.errChan
		if errors[0] != nil {
			// Error in this stage. Stop the next one.
		}
	}()

	// Next stage status.
	go func() {
		defer wg.Done()
		errors[1] = p.nextStage.Wait()

	}()
	wg.Wait()

	// In both cases we need to close the incoming channel of the next stage.
	p.nextStage.Stop()

	return util.ErrorsCoalesce(errors...)
}

func (p *CsvToChainsPipeline) resume() {
	p.IncomingChan = make(chan util.CsvFile)

	// Process files and parse the CSV contents:
	go func() {
		// Spawn a fixed number of file readers.
		wg := sync.WaitGroup{}
		wg.Add(p.numReaders)
		errors := make([]error, p.numReaders)
		for r := 0; r < p.numReaders; r++ {
			r := r
			go func() {
				defer wg.Done()
				for f := range p.IncomingChan {
					errors[r] = p.processFile(f)
				}
			}()
		}
		wg.Wait()

		fmt.Println()
		fmt.Println("Done with incoming files, closing parsed data channel.")

		// Because we are done writing parsed content, close this stage's output channel:
		close(*p.NextStageChan)

		// Report any errors.
		p.errChan <- util.ErrorsCoalesce(errors...)
	}()
}

// processFile processes any File.
// This stage is responsible of parsing the data into X509 certificates and chains.
func (p *CsvToChainsPipeline) processFile(f util.CsvFile) error {
	r, err := f.Open()
	if err != nil {
		return err
	}

	defer p.stats.TotalFilesRead.Add(1) // one more file had been read

	// ingestWithCSV will send data to the cert with chain channel
	if err := p.ingestWithCSV(r); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// ingestWithCSV spawns as many goroutines as specified by p.numParsers,
// that divide the CSV rows and parse them.
// For efficiency reasons, the whole file is read at once in memory, and its rows divided
// from there.
func (p *CsvToChainsPipeline) ingestWithCSV(fileReader io.Reader) error {
	reader := csv.NewReader(fileReader)
	reader.FieldsPerRecord = -1 // don't check number of fields

	type lineAndFields struct {
		lineNo int
		fields []string
	}
	recordsChan := make(chan *lineAndFields)

	wg := sync.WaitGroup{}
	wg.Add(p.numParsers)
	errors := make([]error, p.numParsers)
	for r := 0; r < p.numParsers; r++ {
		go func(r int) {
			defer wg.Done()
			for x := range recordsChan {
				errors[r] = p.parseAndSendToNextStage(x.fields, x.lineNo)
			}
		}(r)
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

	return util.ErrorsCoalesce(errors...)
}

func (p *CsvToChainsPipeline) parseAndSendToNextStage(
	fields []string,
	lineNo int,
) error {
	// First avoid even parsing already expired certs.
	n, err := getExpiration(fields)
	if err != nil {
		return err
	}
	if p.now.After(time.Unix(n, 0)) {
		// Skip this certificate.
		return nil
	}

	// From this point on, we need to parse the certificate.
	rawBytes, err := base64.StdEncoding.DecodeString(fields[CertificateColumn])
	if err != nil {
		return err
	}
	// Update statistics.
	p.stats.ReadBytes.Add(int64(len(rawBytes)))
	p.stats.ReadCerts.Add(1)
	p.stats.UncachedCerts.Add(1)

	// Get the leaf certificate ID.
	certID := common.SHA256Hash32Bytes(rawBytes)
	if p.presence.Contains(&certID) {
		// For some reason this leaf certificate has been ingested already. Skip.
		return nil
	}
	cert, err := ctx509.ParseCertificate(rawBytes)
	if err != nil {
		return err
	}

	if p.now.After(cert.NotAfter) {
		// Don't ingest already expired certificates.
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
		// Update statistics.
		p.stats.ReadBytes.Add(int64(len(rawBytes)))
		p.stats.ReadCerts.Add(1)
		// Check if the parent certificate is in the cache.
		id := common.SHA256Hash32Bytes(rawBytes)
		if !p.presence.Contains(&id) {
			// Not seen before, push it to the DB.
			chain[i], err = ctx509.ParseCertificate(rawBytes)
			if err != nil {
				return fmt.Errorf("at line %d: %s\n%s", lineNo, err, fields[CertChainColumn])
			}
			p.presence.AddIDs([]*common.SHA256Output{&id})
			p.stats.UncachedCerts.Add(1)
		}
		chainIDs[i] = &id
	}
	*p.NextStageChan <- updater.CertWithChainData{
		Cert:          cert,
		CertID:        certID,
		ChainPayloads: chain,
		ChainIDs:      chainIDs,
	}
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
