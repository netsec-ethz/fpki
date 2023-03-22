package util

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/csv"
	"encoding/pem"
	"io"
	"os"
	"strings"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
)

const (
	CertificateColumn = 3
	CertChainColumn   = 4
)

func ReadAllGzippedFile(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	z, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}

	raw, err := io.ReadAll(z)
	if err != nil {
		return nil, err
	}

	err = z.Close()
	if err != nil {
		return nil, err
	}

	err = f.Close()
	return raw, err
}

func LoadCertsFromPEM(buff []byte) ([]*ctx509.Certificate, error) {
	certs := make([]*ctx509.Certificate, 0)
	for len(buff) > 0 {
		var block *pem.Block
		block, buff = pem.Decode(buff)
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := ctx509.ParseTBSCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}

		certs = append(certs, c)
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
	payloads, IDs, parentIDs, names = updater.UnfoldCerts(leafs, chains)
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
