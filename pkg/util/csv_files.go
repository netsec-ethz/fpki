package util

import (
	"compress/gzip"
	"io"
	"os"
)

type CsvFile interface {
	WithFile(string) CsvFile
	Filename() string
	String() string
	Open() (io.Reader, error)
	Close() error
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
