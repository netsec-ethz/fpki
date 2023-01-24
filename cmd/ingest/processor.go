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
	"github.com/netsec-ethz/fpki/pkg/db"
)

type Processor struct {
	BatchSize int
	Conn      db.Conn

	incomingFileCh chan File      // indicates new file(s) with certificates to be ingested
	fromParserCh   chan *CertData // parser data to be sent to SMT and DB\
	batchProcessor *BatchProcessor

	errorCh chan error // errors accumulate here
	doneCh  chan error // the aggregation of all errors. Signals Processor is done
}

type CertData struct {
	Cert      *ctx509.Certificate
	CertChain []*ctx509.Certificate
}

func NewProcessor(conn db.Conn) *Processor {
	p := &Processor{
		BatchSize: 1000,
		Conn:      conn,

		incomingFileCh: make(chan File),
		fromParserCh:   make(chan *CertData),
		batchProcessor: NewBatchProcessor(conn),

		errorCh: make(chan error),
		doneCh:  make(chan error),
	}
	p.start()
	return p
}

func (p *Processor) start() {
	// Process files and parse the CSV contents:
	go func() {
		wg := sync.WaitGroup{}
		for f := range p.incomingFileCh {
			f := f
			wg.Add(1)
			go func() {
				defer wg.Done()
				r, err := f.Open()
				if err != nil {
					p.errorCh <- err
					return
				}
				if err := p.ingestWithCSV(r); err != nil {
					p.errorCh <- err
					return
				}
				if err := f.Close(); err != nil {
					p.errorCh <- err
					return
				}
			}()
		}
		wg.Wait()
		fmt.Println("deleteme done with incoming files, closing parsed data channel")
		// Because we are done writing parsed content, close that channel.
		close(p.fromParserCh)
	}()

	// Process the parsed content into the DB:
	go func() {
		batch := NewBatch()
		for data := range p.fromParserCh {
			batch.AddData(data)
			if batch.Full() {
				p.batchProcessor.Process(batch)
				fmt.Print(".")
				batch = NewBatch()
			}
		}
		// Process last batch, which may have zero size.
		p.batchProcessor.Process(batch)
		fmt.Println()
		p.batchProcessor.Wait()

		fmt.Printf("\ndeleteme done ingesting the certificates. SMT still to go\n\n\n\n")

		// Now start processing the changed domains into the SMT:
		smtProcessor := NewSMTUpdater(p.Conn, nil, 32)
		smtProcessor.Start()
		if err := smtProcessor.Wait(); err != nil {
			fmt.Printf("deleteme error found in SMT processing: %s\n", err)
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
	fmt.Println("deleteme closing incomingFileCh")
	close(p.incomingFileCh)

	// Wait until all data has been processed.
	fmt.Println("deleteme waiting for done signal")
	return <-p.doneCh
}

func (p *Processor) AddGzFiles(fileNames []string) {
	for _, filename := range fileNames {
		p.incomingFileCh <- (&GzFile{}).WithFile(filename)
	}
}

func (p *Processor) AddCsvFiles(fileNames []string) {
	for _, filename := range fileNames {
		p.incomingFileCh <- (&CsvFile{}).WithFile(filename)
	}
}

func (p *Processor) ingestWithCSV(fileReader io.Reader) error {
	reader := csv.NewReader(fileReader)
	reader.FieldsPerRecord = -1 // don't check number of fields
	reader.ReuseRecord = true

	var err error
	var fields []string
	for lineNo := 1; err == nil; lineNo++ {
		fields, err = reader.Read()
		if len(fields) == 0 { // there exist empty lines (e.g. at the end of the gz files)
			continue
		}
		rawBytes, err := base64.StdEncoding.DecodeString(fields[CertificateColumn])
		if err != nil {
			return err
		}
		cert, err := ctx509.ParseCertificate(rawBytes)
		if err != nil {
			return err
		}

		// The certificate chain is a list of base64 strings separated by semicolon (;).
		strs := strings.Split(fields[CertChainColumn], ";")
		chain := make([]*ctx509.Certificate, len(strs))
		for i, s := range strs {
			rawBytes, err = base64.StdEncoding.DecodeString(s)
			if err != nil {
				return fmt.Errorf("at line %d: %s\n%s", lineNo, err, fields[CertChainColumn])
			}
			chain[i], err = ctx509.ParseCertificate(rawBytes)
			if err != nil {
				return fmt.Errorf("at line %d: %s\n%s", lineNo, err, fields[CertChainColumn])
			}
		}
		p.fromParserCh <- &CertData{
			Cert:      cert,
			CertChain: chain,
		}
	}
	return nil
}

func (p *Processor) processErrorChannel() error {
	var errorsFound bool
	fmt.Println("deleteme processing error channel")
	for err := range p.errorCh {
		if err == nil {
			continue
		}
		fmt.Println("deleteme errors found")
		errorsFound = true
		fmt.Fprintf(os.Stderr, "%s\n", err)
	}
	if errorsFound {
		return fmt.Errorf("errors found while processing. See above")
	}
	return nil
}
