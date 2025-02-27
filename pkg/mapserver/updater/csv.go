package updater

import (
	"encoding/base64"
	"fmt"
	"time"
	"unsafe"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/util/noallocs"
)

const (
	CsvBufferSize  = 64 * 1024 * 1024 // 64MB
	TemporaryDir   = "/mnt/data/tmp/"
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

func CreateCsvCerts(
	storage [][][]byte,
	filenameStorage []byte,
	certs []Certificate,
) (string, error) {
	return writeRecordsWithStorage(
		storage,
		writeCSV,
		filenameStorage,
		TemporaryDir+"fpki-ingest-certs-",
		".csv",
		certs,
		recordsForCert,
	)
}

func CreateCsvDirty(
	storage [][][]byte,
	filenameStorage []byte,
	domains []DirtyDomain,
) (string, error) {
	return writeRecordsWithStorage(
		storage,
		writeCSV,
		filenameStorage,
		TemporaryDir+"fpki-ingest-dirty-",
		".csv",
		domains,
		recordsForDirty,
	)
}

func CreateCsvDomains(
	storage [][][]byte,
	filenameStorage []byte,
	domains []DirtyDomain,
) (string, error) {
	return writeRecordsWithStorage(
		storage,
		writeCSV,
		filenameStorage,
		TemporaryDir+"fpki-ingest-domains-",
		".csv",
		domains,
		recordsForDomains,
	)
}

func CreateCsvDomainCerts(
	storage [][][]byte,
	filenameStorage []byte,
	domains []DirtyDomain,
) (string, error) {
	return writeRecordsWithStorage(
		storage,
		writeCSV,
		filenameStorage,
		TemporaryDir+"fpki-ingest-domain_certs-",
		".csv",
		domains,
		recordsForDomainCerts,
	)
}

func writeRecordsWithStorage[T any](
	dst [][][]byte, // with the correct len(dst) == len(data), each len(dst[i]) == len(toRecords(data[i]))
	writerFunc func([]byte, string, string, [][][]byte) (string, error), // The function to write to disk.
	filenameStorage []byte,
	prefix string,
	suffix string,
	data []T,
	toRecords func(dst [][]byte, field T),
) (string, error) {
	for i, d := range data {
		toRecords(dst[i], d)
	}

	return writerFunc(filenameStorage, prefix, suffix, dst[:len(data)])
}

var (
	commaChar   = []byte{','}
	newlineChar = []byte{'\n'}
)

func writeCSV(filenameStorage []byte, prefix, suffix string, storage [][][]byte) (string, error) {
	// Create a temporary file.
	filename, err := noallocs.CreateTempFile(filenameStorage, prefix, suffix)
	if err != nil {
		return "", fmt.Errorf("creating temporary file: %w", err)
	}

	fd, err := noallocs.Open(filenameStorage, filename)
	if err != nil {
		return "", fmt.Errorf("opening temporary file %s: %w", filename, err)
	}

	for _, row := range storage {
		i := 0
		for ; i < min(1, len(row)); i++ {
			if err = noallocs.Write(fd, row[0]); err != nil {
				return "", fmt.Errorf("writing to temporary file %s: %w", filename, err)
			}
		}
		for ; i < len(row); i++ {
			if err = noallocs.Write(fd, commaChar); err != nil {
				return "", fmt.Errorf("writing to temporary file %s: %w", filename, err)
			}
			field := row[i]
			// for _, field := range row {
			if err = noallocs.Write(fd, field); err != nil {
				return "", fmt.Errorf("writing to temporary file %s: %w", filename, err)
			}
		}
		if err = noallocs.Write(fd, newlineChar); err != nil {
			return "", fmt.Errorf("writing to temporary file %s: %w", filename, err)
		}
	}

	if err = noallocs.Close(fd); err != nil {
		return "", fmt.Errorf("closing temporary file %s: %w", filename, err)
	}

	return filename, nil
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
