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
	NumFiles      = 4
	NumParsers    = 32
	NumDechainers = 4
	NumDBWriters  = 32

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
//
// deleteme:
// debugging:
// time go run -tags=trace ./cmd/ingest/ -numfiles 1  -numparsers 4 -numdechainers 2 -numdbworkers 4 -strategy onlyingest ./testdata2/
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
	multiInsertSize := flag.Int("multiinsert", MultiInsertSize, "number of certificates and "+
		"domains inserted at once in the DB")
	numFiles := flag.Int("numfiles", NumFiles, "Number of parallel files being read at once")
	numParsers := flag.Int("numparsers", NumParsers, "Number of line parsers concurrently running")
	numChainToCerts := flag.Int("numdechainers", NumDechainers, "Number of chain unrollers")
	numDBWriters := flag.Int("numdbworkers", NumDBWriters, "Number of concurrent DB writers")
	strategy := flag.String("strategy", "", "strategy to update certificates\n"+
		"\"\": full work. I.e. ingest files, coalesce, and update SMT.\n"+
		"\"onlyingest\": do not coalesce or update SMT after ingesting files.\n"+
		"\"skipingest\": only coalesce payloads of domains in the dirty table and update SMT.\n"+
		"\"onlysmtupdate\": only update the SMT.\n")
	debugMemProfDump := flag.String("memprofdump", "", "write a memory profile to the file "+
		"every time SIGUSR1 is caught")
	fileBatch := flag.Int("filebatch", 0, "process files in batches of this size. If zero, then "+
		"all files are processed in one batch")
	flag.Parse()

	// Connect to DB via local socket, should be faster.
	config := db.NewConfig(
		mysql.WithDefaults(),
		mysql.WithEnvironment(),
		mysql.WithLocalSocket("/var/run/mysqld/mysqld.sock"),
	)
	conn, err := mysql.Connect(config)
	exitIfError(err)

	coalesceFun := func() {}
	smtUpdateFun := func() {}

	var (
		ingestCerts bool
	)

	switch *strategy {
	case "onlyingest":
		ingestCerts = true // But do not fallthrough to also coalesce and update SMT.

	case "":
		ingestCerts = true
		fallthrough
	case "skipingest":
		coalesceFun = func() {
			ctx, span := tr.MT().Start(ctx, "coalesce")
			defer span.End()

			coalescePayloadsForDirtyDomains(ctx, conn)
		}
		fallthrough
	case "onlysmtupdate":
		smtUpdateFun = func() {
			ctx, span := tr.MT().Start(ctx, "smt-update")
			defer span.End()

			updateSMT(ctx, conn)
			cleanupDirty(ctx, conn)
		}
	default:
		exitIfError(fmt.Errorf("bad update strategy: %v", *strategy))
	}

	// If we will ingest certificates, we need a path.
	if ingestCerts && flag.NArg() != 1 {
		flag.Usage()
		return 1
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
	defer stopProfiles()

	if *cpuProfile != "" {
		f, err := os.Create(*cpuProfile)
		exitIfError(err)
		err = pprof.StartCPUProfile(f)
		exitIfError(err)
		defer func() {
			exitIfError(f.Close())
		}()
	}

	// Memprof dump if SIGUSR1.
	if *debugMemProfDump != "" {
		util.RunOnSignal(
			ctx,
			func(s os.Signal) {
				f, err := os.Create(*debugMemProfDump)
				exitIfError(err)
				err = pprof.Lookup("heap").WriteTo(f, 0) // use "heap" or "allocs"
				exitIfError(err)
				exitIfError(f.Close())
			},
			syscall.SIGUSR1,
		)
	}

	// Signals catching:
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sg := <-signals
		fmt.Fprintf(os.Stderr, "\nsignal caught %s\n", sg.String())
		stopProfiles()
		os.Exit(1)
	}()

	if ingestCerts {
		stats := updater.NewStatistics(2*time.Second, printStats)

		// Use the file batcher ingest function.
		forEachFileBatchFun := func(files []string) {
			ctx, span := tr.MT().Start(ctx, "file-ingestion")
			defer span.End()

			proc, err := NewProcessor(
				ctx,
				conn,
				*multiInsertSize,
				stats,
				WithNumFileReaders(*numFiles),
				WithNumToChains(*numParsers),
				WithNumToCerts(*numChainToCerts),
				WithNumDBWriters(*numDBWriters),
			)
			exitIfError(err)

			csvFiles := make([]util.CsvFile, 0, len(files))
			for _, filename := range files {
				f, err := util.LoadCsvFile(filename)
				exitIfError(err)
				csvFiles = append(csvFiles, f)
			}
			proc.AddCsvFiles(csvFiles)

			fmt.Printf("[%s] Starting ingesting files ...\n",
				time.Now().Format(time.StampMilli))
			// Update certificates and chains, and wait until finished.
			proc.Resume()
			exitIfError(proc.Wait())

			// After ingestion.
			coalesceFun()
			smtUpdateFun()
		}

		ingestFilesInBatches(stats, *fileBatch, forEachFileBatchFun)

	} else {
		coalesceFun()
		smtUpdateFun()
	}
	return 0
}

func ingestFilesInBatches(
	stats *updater.Stats,
	fileBatchSize int,
	forEachBatch func([]string),
) {
	// All GZ and CSV files found under the directory of the argument.
	gzFiles, csvFiles := listOurFiles(flag.Arg(0))
	fmt.Printf("# gzFiles: %d, # csvFiles: %d\n", len(gzFiles), len(csvFiles))
	allFileNames := append(gzFiles, csvFiles...)

	// Update the statistics.
	stats.TotalFiles.Store(int64(len(allFileNames)))
	stats.TotalCerts.Store(0)
	for _, fileName := range allFileNames {
		n, err := util.EstimateCertCount(fileName)
		exitIfError(err)
		stats.TotalCerts.Add(int64(n))
	}

	// Default (with size zero) is one batch for all files.
	if fileBatchSize == 0 {
		fileBatchSize = len(allFileNames)
	} else {
		fileBatchSize = min(fileBatchSize, len(allFileNames))
	}
	batchCount := ((len(allFileNames) - 1) / fileBatchSize) + 1

	for i := 0; i < len(allFileNames); i += fileBatchSize {
		s := i
		e := min(i+fileBatchSize, len(allFileNames))

		fmt.Printf("\nProcessing File Batch %d / %d\n", i/fileBatchSize+1, batchCount)
		forEachBatch(allFileNames[s:e])
	}
}

// listOurFiles returns the .gz and .csv files sorted by name.
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
	totalCerts := s.TotalCerts.Load()

	readCerts := s.ReadCerts.Load()
	readBytes := s.ReadBytes.Load()
	writtenCerts := s.WrittenCerts.Load()
	writtenBytes := s.WrittenBytes.Load()

	uncachedCerts := s.UncachedCerts.Load()
	expiredCerts := s.ExpiredCerts.Load()
	secondsSinceStart := float64(time.Since(s.CreateTime).Seconds())

	msg := fmt.Sprintf("%d/%d Files read. %d certs read [%.2f%%], %d written. %.0f certs/s "+
		"(%.0f%% uncached, %.0f%% expired), %.1f | %.1f Mb/s r|w                    ",
		readFiles, totalFiles,
		readCerts,
		float64(readCerts)*100./float64(totalCerts),
		writtenCerts,
		float64(readCerts)/secondsSinceStart,
		float64(uncachedCerts)*100./float64(readCerts),
		float64(expiredCerts)*100./float64(readCerts),
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
