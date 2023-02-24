package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/netsec-ethz/fpki/pkg/db"
)

const (
	NumDBInserters = 64

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
	// Disable indices in DB.
	exitIfError(conn.DisableIndexing("domainEntries"))
	exitIfError(conn.DisableIndexing("updates"))

	// Update certificates and chains.
	proc := NewProcessor(conn)
	proc.AddGzFiles(gzFiles)
	proc.AddCsvFiles(csvFiles)
	exitIfError(proc.Wait())

	// Re-enable indices in DB.
	exitIfError(conn.EnableIndexing("updates"))
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
			f := filepath.Join(dir, e.Name())
			ext := strings.ToLower(filepath.Ext(e.Name()))
			switch ext {
			case ".gz":
				gzFiles = append(gzFiles, f)
			case ".csv":
				csvFiles = append(csvFiles, f)
			}
		} else {
			gzs, csvs := listOurFiles(filepath.Join(dir, e.Name()))
			gzFiles = append(gzFiles, gzs...)
			csvFiles = append(csvFiles, csvs...)
		}
	}
	return
}

func exitIfError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
