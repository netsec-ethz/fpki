package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/db/mysql"
)

const (
	NumFileReaders = 8
	NumParsers     = 64
	// NumDBWriters   = 32
	NumDBWriters = 16

	BatchSize    = 100000           // # of certificates inserted at once.
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
	bundleSize := flag.Uint64("bundlesize", 0, "number of certificates after which a coalesce and "+
		"SMT update must occur. If 0, no limit, meaning coalescing and SMT updating is done once")
	certUpdateStrategy := flag.String("strategy", "keep", "strategy to update certificates\n"+
		"\"overwrite\": always send certificates to DB, even if they exist already.\n"+
		"\"keep\": first check if each certificate exists already in DB before sending it.\n"+
		"\"skipingest\": only coalesce payloads of domains in the dirty table and update SMT.\n"+
		"\"smtupdate\": only update the SMT.\n"+
		`If data transfer to DB is expensive, "keep" is recommended.`)
	flag.Parse()

	// Update strategy.
	var strategy CertificateUpdateStrategy
	var skipIngest bool
	var smtUpdateOnly bool
	switch *certUpdateStrategy {
	case "overwrite":
		strategy = CertificateUpdateOverwrite
	case "keep":
		strategy = CertificateUpdateKeepExisting
	case "skipingest":
		skipIngest = true
	case "smtupdate":
		smtUpdateOnly = true
	default:
		panic(fmt.Errorf("bad update strategy: %v", *certUpdateStrategy))
	}

	// Do we have to ingest certificates?
	ingestCerts := !skipIngest && !smtUpdateOnly

	// If we will ingest certificates, we need a path.
	if ingestCerts && flag.NArg() != 1 {
		flag.Usage()
		return 1
	}

	// Check that we are not using bundles if we are just coalescing or updating the SMT.
	if *bundleSize != 0 && !ingestCerts {
		exitIfError(fmt.Errorf("cannot use bundlesize if strategy is not keep or overwrite"))
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
		mysql.WithLocalSocket("/var/run/mysqld/mysqld.sock"),
	)
	conn, err := mysql.Connect(config)
	exitIfError(err)

	// Load root if any:
	root, err := conn.LoadRoot(ctx)
	exitIfError(err)
	if root == nil {
		fmt.Print("SMT root node is empty. DB should be empty, but not checking.\n\n")
		// TODO(juagargi) check that DB is empty if root is empty.
	}

	if ingestCerts {
		// All GZ and CSV files found under the directory of the argument.
		gzFiles, csvFiles := listOurFiles(flag.Arg(0))
		fmt.Printf("# gzFiles: %d, # csvFiles: %d\n", len(gzFiles), len(csvFiles))

		proc := NewProcessor(conn, strategy)
		// Set parameters to the processor.
		proc.BundleMaxSize = *bundleSize
		proc.OnBundleFinished = func() {
			// Called for intermediate bundles. Need to coalesce, update SMT and clean dirty.
			fmt.Println("Bundle ingestion finished.")
			coalescePayloadsForDirtyDomains(ctx, conn)
			updateSMT(ctx, conn)
			cleanupDirty(ctx, conn)
		}

		// Add the files to the processor.
		proc.AddGzFiles(gzFiles)
		proc.AddCsvFiles(csvFiles)

		// Update certificates and chains, and wait until finished.
		exitIfError(proc.Wait())
	}

	// The certificates had been ingested. If we had set a bundle size, we still need to process
	// the last bundle. If we hadn't, we will process it all.
	if !smtUpdateOnly {
		// Coalesce the payloads of all modified domains.
		coalescePayloadsForDirtyDomains(ctx, conn)
	}

	// Now update the SMT Trie with the changed domains:
	updateSMT(ctx, conn)

	// Cleanup dirty entries.
	cleanupDirty(ctx, conn)

	// Close DB.
	err = conn.Close()
	exitIfError(err)
	return 0
}

func listOurFiles(dir string) (gzFiles, csvFiles []string) {
	entries, err := os.ReadDir(dir)
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

	// Sort the files according to their node number.
	sortByBundleName(gzFiles)
	sortByBundleName(csvFiles)

	return
}

// sortByBundleName expects a slice of filenames of the form X-Y.{csv,gz}.
// After it returns, the slice is sorted according to uint(X).
func sortByBundleName(names []string) {
	sort.Slice(names, func(i, j int) bool {
		a := filenameToFirstSize(names[i])
		b := filenameToFirstSize(names[j])
		return a < b
	})
}

func filenameToFirstSize(name string) uint64 {
	name = filepath.Base(name)
	tokens := strings.Split(name, "-")
	if len(tokens) != 2 {
		exitIfError(fmt.Errorf("filename doesn't follow convention: %s", name))
	}
	n, err := strconv.ParseUint(tokens[0], 10, 64)
	exitIfError(err)
	return n
}

func exitIfError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
