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
)

const (
	CertificateColumn = 3
	CertChainColumn   = 4
)

func Gunzip(filename string) ([]byte, error) {
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

func LoadCertsFromPEM(raw []byte) ([]*ctx509.Certificate, error) {
	certs := make([]*ctx509.Certificate, 0)
	for len(raw) > 0 {
		var block *pem.Block
		block, raw = pem.Decode(raw)
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

// LoadCertsAndChainsFromCSV returns a ready to insert-in-DB collection of IDs and payloads for
// each certificate and its ancestry.
//
// a slice containing N elements, which represent the certificate
// chain from the leaf to the root certificate.
func LoadCertsAndChainsFromCSV(raw []byte) ([]*ctx509.Certificate, error) {
	r := bytes.NewReader(raw)
	reader := csv.NewReader(r)
	reader.FieldsPerRecord = -1 // don't check number of fields

	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	for _, fields := range records {
		if len(fields) == 0 {
			continue
		}

		// Parse the certificate.
		rawBytes, err := base64.StdEncoding.DecodeString(fields[CertificateColumn])
		if err != nil {
			return nil, err
		}
		certID := common.SHA256Hash32Bytes(rawBytes)
		cert, err := ctx509.ParseCertificate(rawBytes)
		if err != nil {
			return nil, err
		}

		// Parse the chain.
		// The certificate chain is a list of base64 strings separated by semicolon (;).
		strs := strings.Split(fields[CertChainColumn], ";")
		chain := make([]*ctx509.Certificate, len(strs))
		chainIDs := make([]*common.SHA256Output, len(strs))
		for i, s := range strs {
			rawBytes, err = base64.StdEncoding.DecodeString(s)
			if err != nil {
				return nil, err
			}
			chain[i], err = ctx509.ParseCertificate(rawBytes)
			if err != nil {
				return nil, err
			}
		}

		_ = certID
		_ = cert
		_ = chainIDs

	}

	return nil, nil
}
