package main

import (
	"compress/gzip"
	"io"
	"os"
)

type File interface {
	WithFile(string) File
	Filename() string
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

func (f *baseFile) Close() error {
	return f.reader.Close()
}

type GzFile struct {
	baseFile

	gzReader *gzip.Reader
}

func (f *GzFile) WithFile(fn string) File {
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

type CsvFile struct {
	baseFile
}

func (f *CsvFile) WithFile(fn string) File {
	f.FileName = fn
	return f
}

func (f *CsvFile) Open() (io.Reader, error) {
	var err error
	f.reader, err = os.Open(f.FileName)
	if err != nil {
		return nil, err
	}
	return f.reader, nil
}
