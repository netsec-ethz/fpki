package main

import (
	"compress/gzip"
	"io"
	"os"
)

type File interface {
	Open() (io.Reader, error)
	Close() error
}

type GzFile struct {
	FileName string
	reader   *os.File
	gzReader *gzip.Reader
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

type CsvFile struct {
	FileName string
	reader   *os.File
}

func (f *CsvFile) Open() (io.Reader, error) {
	var err error
	f.reader, err = os.Open(f.FileName)
	if err != nil {
		return nil, err
	}
	return f.reader, nil
}

func (f *CsvFile) Close() error {
	return f.reader.Close()
}
