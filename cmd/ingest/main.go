package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime/pprof"
	"syscall"
	"time"

	args "github.com/netsec-ethz/fpki/cmd/ingest/cmdflags"
	"github.com/netsec-ethz/fpki/cmd/ingest/csv"
	"github.com/netsec-ethz/fpki/cmd/ingest/journal"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/db/mysql"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	tr "github.com/netsec-ethz/fpki/pkg/tracing"
	"github.com/netsec-ethz/fpki/pkg/util"
)

const (
	LruCacheSize = 10_000_000 // Keep track of the 10 million most seen certificates.
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

	args.ConfigureFlags()

	// Connect to DB via local socket, should be faster.
	config := db.NewConfig(
		mysql.WithDefaults(),
		mysql.WithEnvironment(),
		mysql.WithLocalSocket("/var/run/mysqld/mysqld.sock"),
	)
	conn, err := mysql.Connect(config)
	exitIfError(err)

	var jrnl *journal.Journal
	jrnl, err = journal.NewJournal(*args.JournalFile)
	exitIfError(err)

	coalesceFun := func() {}
	smtUpdateFun := func() {}

	var (
		ingestCerts bool
	)

	switch *args.Strategy {
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
		exitIfError(fmt.Errorf("bad update strategy: %v", *args.Strategy))
	}

	// If we will ingest certificates, we need a path.
	if ingestCerts && flag.NArg() != 1 {
		flag.Usage()
		return 1
	}

	// Profiling:
	stopProfiles := func() {
		if *args.CpuProfile != "" || *args.MemProfile != "" {
			fmt.Fprintln(os.Stderr, "\nStopping profiling")
		}

		if *args.CpuProfile != "" {
			pprof.StopCPUProfile()
		}
		if *args.MemProfile != "" {
			f, err := os.Create(*args.MemProfile)
			exitIfError(err)
			err = pprof.WriteHeapProfile(f)
			exitIfError(err)
		}
	}
	defer stopProfiles()

	if *args.CpuProfile != "" {
		f, err := os.Create(*args.CpuProfile)
		exitIfError(err)
		err = pprof.StartCPUProfile(f)
		exitIfError(err)
		defer func() {
			exitIfError(f.Close())
		}()
	}

	// Memprof dump if SIGUSR1.
	if *args.DebugMemProfDump != "" {
		util.RunOnSignal(
			ctx,
			func(os.Signal) {
				createMemDump(*args.DebugMemProfDump)
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
		// Memory dump file name, if any:
		createMemDump("/tmp/fpki-ingest-crash-memdump.pprof")
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
				*args.MultiInsertSize,
				stats,
				WithNumFileReaders(*args.NumFiles),
				WithNumToChains(*args.NumParsers),
				WithNumToCerts(*args.NumChainToCerts),
				WithNumDBWriters(*args.NumDBWriters),
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

			// Update journal.
			if jrnl != nil {
				err = jrnl.AddCompletedFiles(files)
				exitIfError(err)
			}
		}

		err := ingestFilesInBatches(stats, *args.FileBatch, forEachFileBatchFun)
		exitIfError(err)
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
) error {
	// All GZ and CSV files found under the directory of the argument.
	gzFiles, csvFiles, err := csv.ListCsvFiles(flag.Arg(0))
	if err != nil {
		return err
	}
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

	return nil
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

func createMemDump(filename string) {
	f, err := os.Create(filename)
	exitIfError(err)
	err = pprof.Lookup("heap").WriteTo(f, 0) // use "heap" or "allocs"
	exitIfError(err)
	exitIfError(f.Close())
	fmt.Fprintf(os.Stderr, "\nMemory dumped to %s\n", filename)
}
