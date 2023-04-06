package util

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/csv"
	"encoding/pem"
	"io"
	"io/ioutil"
	"os"
	"strings"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/common"
)

const (
	CertificateColumn = 3
	CertChainColumn   = 4
)

type GzipReader struct {
	f        *os.File
	gzreader *gzip.Reader
}

func (r *GzipReader) Read(buff []byte) (int, error) {
	return r.gzreader.Read(buff)
}

func (r *GzipReader) Close() error {
	if err := r.gzreader.Close(); err != nil {
		return err
	}
	return r.f.Close()
}

func NewGzipReader(filename string) (*GzipReader, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	z, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	return &GzipReader{
		f:        f,
		gzreader: z,
	}, nil
}

func ReadAllGzippedFile(filename string) ([]byte, error) {
	r, err := NewGzipReader(filename)
	if err != nil {
		return nil, err
	}
	buff, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return buff, r.Close()
}

func LoadCertsFromPEMBuffer(buff []byte) ([]*ctx509.Certificate, error) {
	r := bytes.NewReader(buff)
	return LoadCertsWithPEMReader(r)
}

// LoadCertsWithPEMReader uses the reader to read more data to memory if the PEM parsing cannot
// find an appropriate block. If there exists a PEM block bigger than the current buffer, the
// function will double its size and try again, until all data has been read from the reader.
func LoadCertsWithPEMReader(r io.Reader) ([]*ctx509.Certificate, error) {
	storage := make([]byte, 1024)
	var buff []byte
	bytesPending := true

	certs := make([]*ctx509.Certificate, 0)
	for bytesPending {
		// Move len(buff) bytes to beginning of storage.
		n := copy(storage[:], buff)
		// Set buff to be the remaining of the storage.
		buff = storage[n:]

		// Read as much as possible.
		newBytes, err := r.Read(buff)
		if err != nil && err != io.EOF {
			return nil, err
		}
		// Set buff to beginning of storage and until last read byte.
		buff = storage[:n+newBytes]

		if newBytes == 0 {
			if err != io.EOF {
				// Storage support might be too small to fit this PEM block. Increase by double
				// its size and try again; the copy at the beginning of the loop will restore
				// the original contents to this new buffer.
				storage = make([]byte, 2*len(storage))
				continue
			}
			// End of File.
			bytesPending = false
		}

		// Proceed to parse as many CERTIFICATE PEM blocks as possible.
		var block *pem.Block
		for { // do-while block != nil && block.Type == CERTIFICATE
			block, buff = pem.Decode(buff)
			if block == nil {
				// No PEM block found, try to read more data and try again.
				break
			}
			if block.Type != "CERTIFICATE" {
				// Wrong PEM block, try to find another one.
				continue
			}
			// It must be a certificate. Complain if parsing fails.
			c, err := ctx509.ParseTBSCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			certs = append(certs, c)
		}
	}
	return certs, nil
}

// LoadCertsAndChainsFromCSV returns a ready to insert-in-DB collection of the leaf certificate
// payload, its ID, its parent ID, and its names, for each certificate and its ancestry chain.
// The returned names contains nil unless the corresponding certificate is a leaf certificate.
func LoadCertsAndChainsFromCSV(
	fileContents []byte,
) (payloads []*ctx509.Certificate,
	IDs []*common.SHA256Output,
	parentIDs []*common.SHA256Output,
	names [][]string,
	errRet error,
) {

	r := bytes.NewReader(fileContents)
	reader := csv.NewReader(r)
	reader.FieldsPerRecord = -1 // don't check number of fields

	records, err := reader.ReadAll()
	if err != nil {
		errRet = err
		return
	}
	leafs := make([]*ctx509.Certificate, 0, len(payloads))
	chains := make([][]*ctx509.Certificate, 0, len(payloads))
	for _, fields := range records {
		if len(fields) == 0 {
			continue
		}

		cert, err := ParseCertFromCSVField(fields[CertificateColumn])
		if err != nil {
			errRet = err
			return
		}
		leafs = append(leafs, cert)

		// Parse the chain.
		// The certificate chain is a list of base64 strings separated by semicolon (;).
		strs := strings.Split(fields[CertChainColumn], ";")
		chain := make([]*ctx509.Certificate, len(strs))
		for i, s := range strs {
			chain[i], err = ParseCertFromCSVField(s)
			if err != nil {
				errRet = err
				return
			}
		}
		chains = append(chains, chain)
	}

	// Unfold the received certificates.
	payloads, IDs, parentIDs, names = UnfoldCerts(leafs, chains)
	return
}

// ParseCertFromCSVField takes a row from a CSV encoding certs and chains in base64 and returns
// the CT x509 Certificate or error.
func ParseCertFromCSVField(field string) (*ctx509.Certificate, error) {
	// Base64 to raw bytes.
	rawBytes, err := base64.StdEncoding.DecodeString(field)
	if err != nil {
		return nil, err
	}
	// Parse the certificate.
	cert, err := ctx509.ParseCertificate(rawBytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}
