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
	"time"

	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/db/mysql"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	tr "github.com/netsec-ethz/fpki/pkg/tracing"
	"github.com/netsec-ethz/fpki/pkg/util"
)

const (
	NumParsers   = 32
	NumDBWriters = 32

	MultiInsertSize = 10_000     // # of certificates, domains, etc inserted at once.
	LruCacheSize    = 10_000_000 // Keep track of the 10 million most seen certificates.
)

// Times gathered at jupiter, 64 gz files, no CSV
// InnoDB: 									8m 17s
// MyISAM overwrite, no pk (invalid DB):	1m 33s 	374 Mb/s
// MyISAM overwrite, afterwards pk: 		3m 22s	175.9 Mb/s
// MyISAM keep, already with pk:			2m 26s	241.0 Mb/s
//
//	articuno, /mnt/data/certificatestore/test/
//	----------------------------------------
//	#Parsers  |  #DB Writers  |    Time    |
//	----------------------------------------
//	    32    |     128       | 0m49.365s  |   <------ using pointers, but there was a bug.
//	    32    |      32       | 4m23.960s  |
//	   128    |      32       | 4m36.166s  |
//	   128    |     128       | 3m53.511s  |
//	   512    |     128       | 3m39.226s  |
//	----------------------------------------
func main() {
	os.Exit(mainFunction())
}

func mainFunction() int {
	ctx := context.Background()
	defer util.ShutdownFunction()

	tr.SetGlobalTracerName("ingest-cli")
	ctx, span := tr.MT().Start(ctx, "main")
	defer span.End()

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage:\n%s directory\n", os.Args[0])
		flag.PrintDefaults()
	}
	cpuProfile := flag.String("cpuprofile", "", "write a CPU profile to file")
	memProfile := flag.String("memprofile", "", "write a memory profile to file")
	bundleSize := flag.Uint64("bundlesize", 0, "number of certificates after which a coalesce and "+
		"SMT update must occur. If 0, no limit, meaning coalescing and SMT updating is done once")
	numParsers := flag.Int("numparsers", NumParsers, "Number of line parsers concurrently running")
	numDBWriters := flag.Int("numdbworkers", NumDBWriters, "Number of concurrent DB writers")
	certUpdateStrategy := flag.String("strategy", "", "strategy to update certificates\n"+
		"\"\": full work. I.e. ingest files, coalesce, and update SMT.\n"+
		"\"onlyingest\": do not coalesce or update SMT after ingesting files.\n"+
		"\"skipingest\": only coalesce payloads of domains in the dirty table and update SMT.\n"+
		"\"onlysmtupdate\": only update the SMT.\n")
	flag.Parse()

	var (
		ingestCerts   bool
		onlyIngest    bool
		onlySmtUpdate bool
	)
	switch *certUpdateStrategy {
	case "onlyingest":
		onlyIngest = true
		fallthrough // also ingest certs
	case "":
		ingestCerts = true
	case "skipingest":
		// ingestCerts is already false
	case "onlysmtupdate":
		onlySmtUpdate = true
	default:
		panic(fmt.Errorf("bad update strategy: %v", *certUpdateStrategy))
	}

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
		if *cpuProfile != "" || *memProfile != "" {
			fmt.Fprintln(os.Stderr, "\nStopping profiling")
		}

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
		defer func() {
			exitIfError(f.Close())
		}()
	}

	// Signals catching:
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sg := <-signals
		fmt.Fprintf(os.Stderr, "signal caught %s\n", sg.String())
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
		ctx, span := tr.MT().Start(ctx, "file-ingestion")
		defer span.End()

		// All GZ and CSV files found under the directory of the argument.
		gzFiles, csvFiles := listOurFiles(flag.Arg(0))
		fmt.Printf("# gzFiles: %d, # csvFiles: %d\n", len(gzFiles), len(csvFiles))

		bundleProcessing := func() {
			// do not coalesce, or update smt.
			fmt.Println("\nAnother bundle ingestion finished.")
		}
		if !onlyIngest {
			bundleProcessing = func() {
				// Regular operation: coalesce and update SMT.
				// Called for intermediate bundles. Need to coalesce, update SMT and clean dirty.

				ctx, span := tr.MT().Start(ctx, "bundle-ingested")
				defer span.End()

				fmt.Println("\nAnother bundle ingestion finished.")
				coalescePayloadsForDirtyDomains(ctx, conn)
				updateSMT(ctx, conn)
				cleanupDirty(ctx, conn)
			}
		}

		proc, err := NewProcessor(
			ctx,
			conn,
			MultiInsertSize,
			2*time.Second,
			printStats,
			WithNumWorkers(*numParsers),
			WithNumDBWriters(*numDBWriters),
			WithBundleSize(*bundleSize),
			WithOnBundleFinished(bundleProcessing),
		)
		exitIfError(err)

		// Add the files to the processor.
		proc.AddGzFiles(gzFiles)
		proc.AddCsvFiles(csvFiles)

		fmt.Printf("[%s] Starting ingesting files ...\n",
			time.Now().Format(time.StampMilli))
		// Update certificates and chains, and wait until finished.
		proc.Resume()

		exitIfError(proc.Wait())

		stopProfiles()

		return 0
	}

	// The certificates had been ingested. If we had set a bundle size, we still need to process
	// the last bundle. If we hadn't, we will process it all.
	if !onlySmtUpdate {
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

	stopProfiles()

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

func printStats(s *updater.Stats) {
	readFiles := s.TotalFilesRead.Load()
	totalFiles := s.TotalFiles.Load()

	readCerts := s.ReadCerts.Load()
	readBytes := s.ReadBytes.Load()
	writtenCerts := s.WrittenCerts.Load()
	writtenBytes := s.WrittenBytes.Load()

	uncachedCerts := s.UncachedCerts.Load()
	secondsSinceStart := float64(time.Since(s.CreateTime).Seconds())

	msg := fmt.Sprintf("%d/%d Files read. %d certs read, %d written. %.0f certs/s "+
		"(%.0f%% uncached), %.1f | %.1f Mb/s r|w                    ",
		readFiles, totalFiles,
		readCerts, writtenCerts,
		float64(readCerts)/secondsSinceStart,
		float64(uncachedCerts)*100./float64(readCerts),
		float64(readBytes)/1024./1024./secondsSinceStart,
		float64(writtenBytes)/1024./1024./secondsSinceStart,
	)

	fmt.Fprintf(os.Stderr, "%s\r", msg)
}

func exitIfError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
