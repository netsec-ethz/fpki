package main

import (
	"compress/gzip"
	"encoding/base64"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"

	"github.com/netsec-ethz/fpki/pkg/db"
)

const (
	CertificateColumn = 3
	ChainColumn       = 4
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage:\n%s directory\n", os.Args[0])
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
	}

	conn, err := db.Connect(nil)
	exitIfError(err)

	gzFiles, csvFiles := listOurFiles(flag.Arg(0))
	fmt.Printf("# gzFiles: %d, # csvFiles: %d\n", len(gzFiles), len(csvFiles))

	// Truncate DB.
	exitIfError(conn.TruncateAllTables())

	// Disable indices in DB.
	// TODO(juagargi)

	// Update certificates and chains.
	err = updateCertificatesFromFiles(conn, gzFiles, csvFiles)
	exitIfError(err)

	// Re-enable indices in DB.
	// TODO(juagargi)

	// Close DB and check errors.
	err = conn.Close()
	exitIfError(err)
}

func listOurFiles(dir string) (gzFiles, csvFiles []string) {
	entries, err := ioutil.ReadDir(dir)
	exitIfError(err)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if e.Name() == "bundled" {
			// Use all *.gz in this directory.
			d := filepath.Join(dir, e.Name())
			gzFiles, err = filepath.Glob(fmt.Sprintf("%s/*.gz", d))
			exitIfError(err)
			csvFiles, err = filepath.Glob(fmt.Sprintf("%s/*.csv", dir))
			exitIfError(err)
		} else {
			gzs, csvs := listOurFiles(filepath.Join(dir, e.Name()))
			gzFiles = append(gzFiles, gzs...)
			csvFiles = append(csvFiles, csvs...)
		}
	}
	return
}

func updateCertificatesFromFiles(conn db.Conn, gzFiles, csvFiles []string) error {
	const N = 2
	exitIfError(processCollection(conn, gzFiles, N, func(fileNameCh chan string) error {
		return updateFromGzFileName(conn, fileNameCh)
	}))

	exitIfError(processCollection(conn, csvFiles, N, func(fileNameCh chan string) error {
		return updateFromFileName(conn, fileNameCh)
	}))

	return nil
}

func processCollection(conn db.Conn, fileNames []string, N int,
	fcn func(fileNameCh chan string) error) error {

	// Use a channel to dispatch batches to go routines.
	fileNameCh := make(chan string)

	errorCh := processConcurrently(conn, N, func() error {
		return fcn(fileNameCh)
	})
	// Send the GZ file names to the channel:
	for _, f := range fileNames {
		fileNameCh <- f
	}
	close(fileNameCh)

	fmt.Println("deleteme 10")
	// If there had been any errors, report them and return an error as well.
	var errorsFound bool
	fmt.Println("deleteme 31")
	for err := range errorCh {
		fmt.Println("deleteme 32")
		if err == nil {
			continue
		}
		errorsFound = true
		fmt.Fprintf(os.Stderr, "%s\n", err)
		fmt.Println("deleteme ---------------")
	}

	fmt.Println("deleteme 41")
	if errorsFound {
		return fmt.Errorf("found errors")
	}
	return nil
}

func processConcurrently(conn db.Conn, N int, fcn func() error) chan error {
	errorCh := make(chan error)
	go func() {
		// Use a WaitGroup to wait for all go routines to finish.
		wg := sync.WaitGroup{}
		// Span N go routines.
		wg.Add(N) // TODO(juagargi) remove N and span as many routines as files.
		for i := 0; i < N; i++ {
			go func() {
				fmt.Println("deleteme 20")
				defer wg.Done()
				errorCh <- fcn()
				fmt.Println("deleteme 22")
			}()
		}
		fmt.Println("deleteme 19")
		wg.Wait()
		fmt.Println("deleteme 29")
		close(errorCh)
		fmt.Println("deleteme 30")
	}()

	return errorCh
}

func updateFromGzFileName(conn db.Conn, fileNameCh chan string) error {
	for filename := range fileNameCh {
		fmt.Printf("deleteme BEGIN WORK with %s\n", filename)
		f, err := os.Open(filename)
		if err != nil {
			return err
		}
		gz, err := gzip.NewReader(f)
		if err != nil {
			return err
		}

		if err := updateFromCSV(conn, gz); err != nil {
			return err
		}

		if err := gz.Close(); err != nil {
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		fmt.Printf("deleteme END WORK with %s\n", filename)
	}
	return nil
}

func updateFromFileName(conn db.Conn, fileNameCh chan string) error {
	for filename := range fileNameCh {
		f, err := os.Open(filename)
		if err != nil {
			return err
		}
		if err := updateFromCSV(conn, f); err != nil {
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
	return nil
}

func updateFromCSV(conn db.Conn, fileReader io.Reader) error {
	reader := csv.NewReader(fileReader)
	reader.FieldsPerRecord = -1 // don't check number of fields
	reader.ReuseRecord = true

	var err error
	var fields []string
	for lineNo := 1; err == nil; lineNo++ {
		fields, err = reader.Read()
		if len(fields) == 0 { // there exist empty lines (e.g. at the end of the gz files)
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(fields[CertificateColumn])
		if err != nil {
			return err
		}
		_ = raw
	}
	return nil
}

func exitIfError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
		os.Exit(1)
	}
}
