package util

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// gzCsvFilename matches with the name of the gz files is e.g. "0-100005.gz".
var gzCsvFilename = regexp.MustCompile(`^(\d+)-(\d+).(?:gz|csv)$`)

func EstimateCertCount(filename string) (uint, error) {
	indices, err := filenameToIndices(filename)
	if err != nil {
		return 0, err
	}

	return indices[1] - indices[0] + 1, nil
}

func CsvFilenameToFirstIndex(filename string) (uint, error) {
	indices, err := filenameToIndices(filename)
	if err != nil {
		return 0, err
	}

	return indices[0], nil
}

func filenameToIndices(filename string) ([2]uint, error) {
	filename = filepath.Base(filename)
	errBadFilename := fmt.Errorf(
		`estimating certificate count from filename "%s": unexpected name`,
		filename)
	groups := gzCsvFilename.FindStringSubmatch(filename)
	if len(groups) != 3 {
		return [2]uint{}, errBadFilename
	}

	first, err := strconv.Atoi(groups[1])
	if err != nil {
		return [2]uint{}, errBadFilename
	}

	last, err := strconv.Atoi(groups[2])
	if err != nil {
		return [2]uint{}, errBadFilename
	}

	if first > last {
		return [2]uint{}, fmt.Errorf("%s: first > last", errBadFilename)
	}

	return [2]uint{uint(first), uint(last)}, nil
}

// SortByBundleName expects a slice of filenames of the form X-Y.{csv,gz}.
// After it returns, the slice is sorted according to uint(X).
func SortByBundleName(names []string) error {
	var errInSorting error
	sort.Slice(names, func(i, j int) bool {
		a, err := CsvFilenameToFirstIndex(names[i])

		if err != nil {
			errInSorting = err
			return false
		}
		b, err := CsvFilenameToFirstIndex(names[j])
		if err != nil {
			errInSorting = err
			return false
		}
		return a < b
	})
	return errInSorting
}

func SearchByBundleName(names []string, name string) (int, error) {
	return 0, nil
}

type CsvFile interface {
	WithFile(string) CsvFile
	Filename() string
	String() string
	Open() (io.Reader, error)
	Close() error
}

func LoadCsvFile(fileName string) (CsvFile, error) {
	var f CsvFile
	switch strings.ToLower(filepath.Ext(fileName)) {
	case ".gz":
		f = &GzFile{}
	case ".csv":
		f = &UncompressedFile{}
	default:
		return nil, fmt.Errorf("unknown CSV file type for %s", fileName)
	}
	return f.WithFile(fileName), nil
}

type baseFile struct {
	FileName string
	reader   *os.File
}

func (f *baseFile) Filename() string {
	return f.FileName
}

func (f *baseFile) String() string {
	return f.FileName
}

func (f *baseFile) Close() error {
	return f.reader.Close()
}

type GzFile struct {
	baseFile

	gzReader *gzip.Reader
}

var _ CsvFile = (*GzFile)(nil)

func (f *GzFile) WithFile(fn string) CsvFile {
	f.FileName = fn
	return f
}

func (f *GzFile) Open() (io.Reader, error) {
	var err error
	f.reader, err = os.Open(f.FileName)
	if err != nil {
		return nil, err
	}
	f.gzReader, err = gzip.NewReader(f.reader)
	if err != nil {
		return nil, err
	}
	return f.gzReader, nil
}

func (f *GzFile) Close() error {
	if err := f.gzReader.Close(); err != nil {
		return err
	}
	return f.reader.Close()
}

// TODO: rename
type UncompressedFile struct {
	baseFile
}

var _ CsvFile = (*UncompressedFile)(nil)

func (f *UncompressedFile) WithFile(fn string) CsvFile {
	f.FileName = fn
	return f
}

func (f *UncompressedFile) Open() (io.Reader, error) {
	var err error
	f.reader, err = os.Open(f.FileName)
	if err != nil {
		return nil, err
	}
	return f.reader, nil
}
