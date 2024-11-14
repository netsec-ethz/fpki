package updater

import (
	"bufio"
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"os"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
)

const (
	CsvBufferSize = 64 * 1024 * 1024 // 64MB
	TemporaryDir  = "/mnt/data/tmp"
)

func CreateCsvCerts(certs []Certificate) (string, error) {
	return writeToCSV("fpki-ingest-certs-*.csv", certs, func(c Certificate) []string {
		return []string{
			// 4 columns: ID, parentID, expTime, payload.
			idToBase64(c.CertID),
			idOrNilToBase64(c.ParentID),
			timeToString(c.Cert.NotAfter),
			bytesToBase64(c.Cert.Raw),
		}
	})
}

func CreateCsvDirty(domains []DirtyDomain) (string, error) {
	return writeToCSV("fpki-ingest-dirty-*.csv", domains, func(d DirtyDomain) []string {
		return []string{
			// 1 column: ID.
			idToBase64(d.DomainID),
		}
	})
}

func CreateCsvDomains(domains []DirtyDomain) (string, error) {
	return writeToCSV("fpki-ingest-domains-*.csv", domains, func(d DirtyDomain) []string {
		return []string{
			// 2 columns: ID, name.
			idToBase64(d.DomainID),
			d.Name,
		}
	})
}

func CreateCsvDomainCerts(domains []DirtyDomain) (string, error) {
	return writeToCSV("fpki-ingest-domain_certs-*.csv", domains, func(d DirtyDomain) []string {
		return []string{
			// 2 columns:
			idToBase64(d.DomainID),
			idToBase64(d.CertID),
		}
	})
}

func writeToCSV[T any](preffix string, data []T, toRecords func(T) []string) (string, error) {
	records := make([][]string, len(data))
	for i, d := range data {
		records[i] = toRecords(d)
	}

	// Create a temporary file.
	tempFile, err := os.CreateTemp(TemporaryDir, preffix)
	if err != nil {
		return "", fmt.Errorf("creating temporary file: %w", err)
	}

	errFcn := func(err error) (string, error) {
		return "", fmt.Errorf("writing CSV file: %w", err)
	}

	w := bufio.NewWriterSize(tempFile, CsvBufferSize)
	csv := csv.NewWriter(w)

	csv.WriteAll(records)
	csv.Flush()

	if err := w.Flush(); err != nil {
		return errFcn(err)

	}
	if err := tempFile.Close(); err != nil {
		return errFcn(err)
	}

	return tempFile.Name(), nil
}

func idToBase64(id common.SHA256Output) string {
	return bytesToBase64(id[:])
}

func idOrNilToBase64(idPtr *common.SHA256Output) string {
	if idPtr == nil {
		return ""
	}
	return bytesToBase64(idPtr[:])
}

func bytesToBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func timeToString(t time.Time) string {
	return t.Format(time.DateTime)
}
