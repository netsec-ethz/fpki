package main

import (
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	ctx509 "github.com/google/certificate-transparency-go/x509"

	"github.com/netsec-ethz/fpki/cmd/ingest/cache"
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/util"
)

// Processor is the pipeline that takes file names and process them into certificates
// inside the DB and SMT. It is composed of several different stages,
// described in the `start` method.
type Processor struct {
	Conn  db.Conn
	cache cache.Cache // IDs of certificates pushed to DB.
	now   time.Time

	incomingFileCh    chan util.CsvFile       // New files with certificates to be ingested
	certWithChainChan chan *CertWithChainData // After parsing files
	nodeChan          chan *CertificateNode   // After finding parents, to be sent to DB and SMT
	batchProcessor    *CertificateProcessor   // Processes certificate nodes (with parent pointer)

	errorCh chan error // Errors accumulate here
	doneCh  chan error // Signals Processor is done
}

type CertWithChainData struct {
	CertID        *common.SHA256Output   // The ID (the SHA256) of the certificate.
	Cert          *ctx509.Certificate    // The payload of the certificate.
	ChainIDs      []*common.SHA256Output // The trust chain of the certificate.
	ChainPayloads []*ctx509.Certificate  // The payloads of the chain. Is nil if already cached.
}

func NewProcessor(conn db.Conn, certUpdateStrategy CertificateUpdateStrategy) *Processor {
	nodeChan := make(chan *CertificateNode)
	p := &Processor{
		Conn:              conn,
		cache:             cache.NewNoCache(),
		now:               time.Now(),
		incomingFileCh:    make(chan util.CsvFile),
		certWithChainChan: make(chan *CertWithChainData),
		nodeChan:          nodeChan,
		batchProcessor:    NewCertProcessor(conn, nodeChan, certUpdateStrategy),

		errorCh: make(chan error),
		doneCh:  make(chan error),
	}
	p.start()
	return p
}

// start starts the pipeline. The pipeline consists on the following transformations:
// - File to rows.
// - Row to certificate with chain.
// - Certificate with chain to certificate with immediate parent.
// This pipeline ends here, and it's picked up by other processor.
// Each stage (transformation) is represented by a goroutine spawned in this start function.
// Each stage reads from the previous channel and outputs to the next channel.
// Each stage closes the channel it outputs to.
func (p *Processor) start() {
	// Process files and parse the CSV contents:
	go func() {
		// Spawn a fixed number of file readers.
		wg := sync.WaitGroup{}
		wg.Add(NumFileReaders)
		for r := 0; r < NumFileReaders; r++ {
			go func() {
				defer wg.Done()
				for f := range p.incomingFileCh {
					p.processFile(f)
				}
			}()
		}
		wg.Wait()
		fmt.Println()
		fmt.Println("Done with incoming files, closing parsed data channel.")
		// Because we are done writing parsed content, close this stage's output channel:
		close(p.certWithChainChan)
	}()

	// Process the parsed content into the DB, and from DB into SMT:
	go func() {
		for data := range p.certWithChainChan {
			certs, certIDs, parentIDs, names := util.UnfoldCert(data.Cert, data.CertID,
				data.ChainPayloads, data.ChainIDs)
			for i := range certs {
				p.nodeChan <- &CertificateNode{
					CertID:   certIDs[i],
					Cert:     certs[i],
					ParentID: parentIDs[i],
					Names:    names[i],
				}
			}
		}
		// This stage has finished, close the output channel:
		close(p.nodeChan)

		// Wait for the next stage to finish
		p.batchProcessor.Wait()

		// There is no more processing to do, close the errors channel and allow the
		// error processor to finish.
		close(p.errorCh)
	}()

	go func() {
		// Print errors and return error if there was any error printed:
		p.doneCh <- p.processErrorChannel()
	}()
}

func (p *Processor) Wait() error {
	// Close the parsing and incoming channels:
	close(p.incomingFileCh)

	// Wait until all data has been processed.
	return <-p.doneCh
}

// AddGzFiles adds a CSV .gz file to the initial stage.
// It blocks until it is accepted.
func (p *Processor) AddGzFiles(fileNames []string) {
	for _, filename := range fileNames {
		p.incomingFileCh <- (&util.GzFile{}).WithFile(filename)
	}
}

// AddGzFiles adds a .csv file to the initial stage.
// It blocks until it is accepted.
func (p *Processor) AddCsvFiles(fileNames []string) {
	for _, filename := range fileNames {
		p.incomingFileCh <- (&util.UncompressedFile{}).WithFile(filename)
	}
}

// processFile processes any File.
// This stage is responsible of parsing the data into X509 certificates and chains.
func (p *Processor) processFile(f util.CsvFile) {
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
func (p *Processor) ingestWithCSV(fileReader io.Reader) error {
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

		// Update statistics.
		p.batchProcessor.ReadBytes.Add(int64(len(rawBytes)))
		p.batchProcessor.ReadCerts.Inc()
		p.batchProcessor.UncachedCerts.Inc()

		if p.now.After(cert.NotAfter) {
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
			p.batchProcessor.ReadBytes.Add(int64(len(rawBytes)))
			p.batchProcessor.ReadCerts.Inc()
			// Check if the parent certificate is in the cache.
			id := common.SHA256Hash32Bytes(rawBytes)
			if !p.cache.Contains(&id) {
				// Not seen before, push it to the DB.
				chain[i], err = ctx509.ParseCertificate(rawBytes)
				if err != nil {
					return fmt.Errorf("at line %d: %s\n%s", lineNo, err, fields[CertChainColumn])
				}
				p.cache.AddIDs([]*common.SHA256Output{&id})
				p.batchProcessor.UncachedCerts.Inc()
			}
			chainIDs[i] = &id
		}
		p.certWithChainChan <- &CertWithChainData{
			Cert:          cert,
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

// processErrorChannel outputs the errors it encounters in the errors channel.
// Returns with error if any is found, or nil if no error.
func (p *Processor) processErrorChannel() error {
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
