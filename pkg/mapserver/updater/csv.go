package updater

import (
	"bufio"
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"os"
	"time"
	"unsafe"

	"github.com/netsec-ethz/fpki/pkg/common"
)

const (
	CsvBufferSize  = 64 * 1024 * 1024 // 64MB
	TemporaryDir   = "/mnt/data/tmp"
	MaxFieldLength = 1024 * 1024 // 1MB
)

func CreateStorage(nRows, nCols int, fieldLengths ...int) [][][]byte {
	storage := make([][][]byte, nRows)
	for i := range storage {
		storage[i] = make([][]byte, nCols)
		for j := range storage[i] {
			storage[i][j] = make([]byte, 0, fieldLengths[j])
		}
	}
	return storage
}

func CreateCsvCerts(storage [][][]byte, certs []Certificate) (string, error) {
	return writeRecordsWithStorage(storage, writeCSV, "fpki-ingest-certs-*.csv",
		certs, recordsForCert)
}

func CreateCsvDirty(storage [][][]byte, domains []DirtyDomain) (string, error) {
	return writeRecordsWithStorage(storage, writeCSV, "fpki-ingest-dirty-*.csv",
		domains, recordsForDirty)
}

func CreateCsvDomains(storage [][][]byte, domains []DirtyDomain) (string, error) {
	return writeRecordsWithStorage(storage, writeCSV, "fpki-ingest-domains-*.csv",
		domains, recordsForDomains)
}

func CreateCsvDomainCerts(storage [][][]byte, domains []DirtyDomain) (string, error) {
	return writeRecordsWithStorage(storage, writeCSV, "fpki-ingest-domain_certs-*.csv",
		domains, recordsForDomainCerts)
}

func writeRecordsWithStorage[T any](
	dst [][][]byte, // with the correct len(dst) == len(data), each len(dst[i]) == len(toRecords(data[i]))
	writerFunc func(string, [][][]byte) (string, error), // The function to write to disk.
	prefix string,
	data []T,
	toRecords func(dst [][]byte, field T),
) (string, error) {
	for i, d := range data {
		toRecords(dst[i], d)
	}

	return writerFunc(prefix, dst[:len(data)])
}

func writeCSV(preffix string, storage [][][]byte) (string, error) {
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

	// Convert to lines.
	lines := make([][]string, len(storage))
	for i, lineByteSlices := range storage {
		lines[i] = make([]string, len(lineByteSlices))
		for j := range lineByteSlices {
			if len(lineByteSlices[j]) > 0 {
				a := &lineByteSlices[j][0]
				lines[i][j] = unsafe.String(a, len(lineByteSlices[j]))
			}
		}
	}

	csv.WriteAll(lines)
	csv.Flush()

	if err := w.Flush(); err != nil {
		return errFcn(err)

	}
	if err := tempFile.Close(); err != nil {
		return errFcn(err)
	}

	return tempFile.Name(), nil
}

func recordsForCert(dst [][]byte, c Certificate) {
	// 4 columns: ID, parentID, expTime, payload.
	idToBase64WithStorage(&dst[0], c.CertID)
	idOrNilToBase64WithStorage(&dst[1], c.ParentID)
	timeToStringWithStorage(&dst[2], c.Cert.NotAfter)
	bytesToBase64WithStorage(&dst[3], c.Cert.Raw)
}

func recordsForDirty(dst [][]byte, d DirtyDomain) {
	// 1 column: ID.
	idToBase64WithStorage(&dst[0], d.DomainID)
}

func recordsForDomains(dst [][]byte, d DirtyDomain) {
	// 2 columns: ID, name.
	idToBase64WithStorage(&dst[0], d.DomainID)
	stringToStorage(&dst[1], d.Name)
}

func recordsForDomainCerts(dst [][]byte, d DirtyDomain) {
	// 2 columns:
	idToBase64WithStorage(&dst[0], d.DomainID)
	idToBase64WithStorage(&dst[1], d.CertID)
}

func idToBase64WithStorage(storage *[]byte, id common.SHA256Output) string {
	return bytesToBase64WithStorage(storage, id[:])
}

func idOrNilToBase64WithStorage(storage *[]byte, idPtr *common.SHA256Output) string {
	if idPtr == nil {
		*storage = (*storage)[:0]
		return ""
	}
	return bytesToBase64WithStorage(storage, idPtr[:])
}

func bytesToBase64WithStorage(storage *[]byte, b []byte) string {
	*storage = (*storage)[:0]
	base64.StdEncoding.AppendEncode(*storage, b)
	*storage = (*storage)[:base64.StdEncoding.EncodedLen(len(b))]
	return unsafe.String(&((*storage)[0]), len(*storage))
}

func timeToStringWithStorage(storage *[]byte, t time.Time) string {
	*storage = (*storage)[:0]
	*storage = t.AppendFormat(*storage, time.DateTime)
	return unsafe.String(&((*storage)[0]), len(*storage))
}

func stringToStorage(storage *[]byte, s string) {
	*storage = (*storage)[:0]
	*storage = append(*storage, []byte(s)...)
}
