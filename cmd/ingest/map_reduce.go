package main

import (
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"io"
	"strings"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/db"
)

type MapReduce struct {
	BatchSize int
	Conn      db.Conn
	Done      chan struct{}

	fromParserCh chan *CertData
}

type CertData struct {
	Cert      *ctx509.Certificate
	CertChain []*ctx509.Certificate
}

func NewMapReduce(conn db.Conn) *MapReduce {
	mr := &MapReduce{
		BatchSize: 1000,
		Conn:      conn,
		Done:      make(chan struct{}),

		fromParserCh: make(chan *CertData),
	}
	mr.Process()
	return mr
}

func (mr *MapReduce) Process() {
	go func() {
		for data := range mr.fromParserCh {
			cn := data.Cert.Subject.CommonName
			// fmt.Printf("CN: %s\n", cn)
			_ = cn
		}
	}()
}

func (mr *MapReduce) IngestWithCSV(fileReader io.Reader) error {
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
		mr.fromParserCh <- &CertData{
			Cert:      cert,
			CertChain: chain,
		}
	}
	return nil
}
