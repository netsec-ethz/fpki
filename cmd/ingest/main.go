package main

import (
	"compress/gzip"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"

	"github.com/netsec-ethz/fpki/pkg/db"
)

const (
	CertificateColumn = 3
	CertChainColumn   = 4
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

	const N = 2
	mapReduce := NewMapReduce(conn)

	// Disable indices in DB.
	exitIfError(conn.DisableIndexing("domainEntries"))

	// Update certificates and chains.
	err = updateCertificatesFromFiles(mapReduce, N, gzFiles, csvFiles)
	exitIfError(err)

	// <-mapReduce.Done

	// Re-enable indices in DB.
	exitIfError(conn.EnableIndexing("domainEntries"))

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

func updateCertificatesFromFiles(proc *Processor, N int, gzFiles, csvFiles []string) error {
	exitIfError(processCollection(gzFiles, N, func(fileNameCh chan string) error {
		return updateFromGzFileName(proc, fileNameCh)
	}))

	exitIfError(processCollection(csvFiles, N, func(fileNameCh chan string) error {
		return updateFromFileName(proc, fileNameCh)
	}))

	return nil
}

func processCollection(fileNames []string, N int,
	fcn func(fileNameCh chan string) error) error {

	// Use a channel to dispatch batches to go routines.
	fileNameCh := make(chan string)

	errorCh := processConcurrently(N, func() error {
		return fcn(fileNameCh)
	})
	// Send the GZ file names to the channel:
	for _, f := range fileNames {
		fileNameCh <- f
	}
	close(fileNameCh)

	// fmt.Println("deleteme 10")
	// If there had been any errors, report them and return an error as well.
	var errorsFound bool
	// fmt.Println("deleteme 31")
	for err := range errorCh {
		// fmt.Println("deleteme 32")
		if err == nil {
			continue
		}
		errorsFound = true
		fmt.Fprintf(os.Stderr, "%s\n", err)
		// fmt.Println("deleteme ---------------")
	}

	// fmt.Println("deleteme 41")
	if errorsFound {
		return fmt.Errorf("found errors")
	}
	return nil
}

func processConcurrently(N int, fcn func() error) chan error {
	errorCh := make(chan error)
	go func() {
		// Use a WaitGroup to wait for all go routines to finish.
		wg := sync.WaitGroup{}
		// Span N go routines.
		wg.Add(N) // TODO(juagargi) remove N and span as many routines as files.
		for i := 0; i < N; i++ {
			go func() {
				// fmt.Println("deleteme 20")
				defer wg.Done()
				errorCh <- fcn()
				// fmt.Println("deleteme 22")
			}()
		}
		// fmt.Println("deleteme 19")
		wg.Wait()
		// fmt.Println("deleteme 29")
		close(errorCh)
		// fmt.Println("deleteme 30")
	}()

	return errorCh
}

func updateFromGzFileName(proc *Processor, fileNameCh chan string) error {
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

		if err := proc.IngestWithCSV(gz); err != nil {
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

func updateFromFileName(proc *Processor, fileNameCh chan string) error {
	for filename := range fileNameCh {
		f, err := os.Open(filename)
		if err != nil {
			return err
		}
		if err := proc.IngestWithCSV(f); err != nil {
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
	return nil
}

func exitIfError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
