package main

import (
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
)

// Processor is the pipeline that takes file names and process them into certificates
// inside the DB and SMT. It is composed of several different stages,
// described in the `start` method.
type Processor struct {
	Conn  db.Conn
	cache *PresenceCache // IDs of certificates pushed to DB.

	incomingFileCh    chan File               // New files with certificates to be ingested
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
		cache:             NewPresenceCache(),
		incomingFileCh:    make(chan File),
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
			certs, certIDs, parents, parentIDs := updater.UnfoldCert(data.Cert, data.CertID,
				data.ChainPayloads, data.ChainIDs)
			for i := range certs {
				p.nodeChan <- &CertificateNode{
					CertID:   certIDs[i],
					Cert:     certs[i],
					ParentID: parentIDs[i],
					Parent:   parents[i],
					IsLeaf:   i == 0, // Only the first certificate is a leaf.
				}
			}
		}
		// This stage has finished, close the output channel:
		close(p.nodeChan)

		// Wait for the next stage to finish
		p.batchProcessor.Wait()

		// Now start processing the changed domains into the SMT:
		smtProcessor := NewSMTUpdater(p.Conn, nil, 32)
		smtProcessor.Start()
		if err := smtProcessor.Wait(); err != nil {
			p.errorCh <- err
		}

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
		p.incomingFileCh <- (&GzFile{}).WithFile(filename)
	}
}

// AddGzFiles adds a .csv file to the initial stage.
// It blocks until it is accepted.
func (p *Processor) AddCsvFiles(fileNames []string) {
	for _, filename := range fileNames {
		p.incomingFileCh <- (&CsvFile{}).WithFile(filename)
	}
}

// processFile processes any File.
// This stage is responsible of parsing the data into X509 certificates and chains.
func (p *Processor) processFile(f File) {
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
		p.batchProcessor.WrittenBytes.Add(int64(len(rawBytes)))
		p.batchProcessor.WrittenCerts.Inc()
		p.batchProcessor.UncachedCerts.Inc()

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
			p.batchProcessor.WrittenBytes.Add(int64(len(rawBytes)))
			p.batchProcessor.WrittenCerts.Inc()
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
