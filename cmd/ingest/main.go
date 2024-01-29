package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/pprof"
	"syscall"

	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/db/mysql"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
)

const (
	NumFileReaders = 8
	NumParsers     = 64
	NumDBWriters   = 32

	BatchSize    = 1000             // # of certificates inserted at once.
	LruCacheSize = 10 * 1000 * 1000 // Keep track of the 10 million most seen certificates.
)

const (
	CertificateColumn = 3
	CertChainColumn   = 4
)

// Times gathered at jupiter, 64 gz files, no CSV
// InnoDB: 									8m 17s
// MyISAM overwrite, no pk (invalid DB):	1m 33s 	374 Mb/s
// MyISAM overwrite, afterwards pk: 		3m 22s	175.9 Mb/s
// MyISAM keep, already with pk:			2m 26s	241.0 Mb/s

func main() {
	os.Exit(mainFunction())
}
func mainFunction() int {
	ctx := context.Background()

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage:\n%s directory\n", os.Args[0])
		flag.PrintDefaults()
	}
	cpuProfile := flag.String("cpuprofile", "", "write a CPU profile to file")
	memProfile := flag.String("memprofile", "", "write a memory profile to file")
	certUpdateStrategy := flag.String("strategy", "keep", "strategy to update certificates\n"+
		"\"overwrite\": always send certificates to DB, even if they exist already.\n"+
		"\"keep\": first check if each certificate exists already in DB before sending it.\n"+
		"\"coalesce\": only coalesce payloads of domains in the dirty table.\n"+
		`If data transfer to DB is expensive, "keep" is recommended.`)
	flag.Parse()

	// Update strategy.
	var strategy CertificateUpdateStrategy
	var coalesceOnly bool
	switch *certUpdateStrategy {
	case "overwrite":
		strategy = CertificateUpdateOverwrite
	case "keep":
		strategy = CertificateUpdateKeepExisting
	case "coalesce":
		coalesceOnly = true
	default:
		panic(fmt.Errorf("bad update strategy: %v", *certUpdateStrategy))
	}
	if !coalesceOnly && flag.NArg() != 1 {
		flag.Usage()
		return 1
	}

	// Profiling:
	stopProfiles := func() {
		if *cpuProfile != "" {
			pprof.StopCPUProfile()
		}
		if *memProfile != "" {
			f, err := os.Create(*memProfile)
			exitIfError(err)
			err = pprof.WriteHeapProfile(f)
			exitIfError(err)
		}
	}
	if *cpuProfile != "" {
		f, err := os.Create(*cpuProfile)
		exitIfError(err)
		err = pprof.StartCPUProfile(f)
		exitIfError(err)
	}
	defer stopProfiles()

	// Signals catching:
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signals
		stopProfiles()
		os.Exit(1)
	}()

	// Connect to DB via local socket, should be faster.
	config := db.NewConfig(
		mysql.WithDefaults(),
		mysql.WithEnvironment(),
	)
	conn, err := mysql.Connect(config)
	exitIfError(err)

	// Load root if any:
	root, err := conn.LoadRoot(ctx)
	exitIfError(err)
	if root == nil {
		fmt.Print("Empty root!!. DB should be empty, but not checking.\n\n")
		// TODO(juagargi) check that DB is empty if root is empty.
	}

	if !coalesceOnly {
		// All GZ and CSV files found under the directory of the argument.
		gzFiles, csvFiles := listOurFiles(flag.Arg(0))
		fmt.Printf("# gzFiles: %d, # csvFiles: %d\n", len(gzFiles), len(csvFiles))

		// Update certificates and chains.
		proc := NewProcessor(conn, strategy)
		proc.AddGzFiles(gzFiles)
		proc.AddCsvFiles(csvFiles)
		exitIfError(proc.Wait())
	}
	// Coalesce the payloads of all modified domains.
	CoalescePayloadsForDirtyDomains(ctx, conn)

	// Now update the SMT Trie with the changed domains:
	fmt.Println("Starting SMT update ...")
	err = updater.UpdateSMT(ctx, conn)
	exitIfError(err)
	fmt.Println("Done SMT update.")

	// Cleanup dirty entries.
	err = conn.CleanupDirty(ctx)
	exitIfError(err)

	// Close DB.
	err = conn.Close()
	exitIfError(err)
	return 0
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

func exitIfError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
