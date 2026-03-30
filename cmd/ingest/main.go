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
	if err := mainFunction(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func mainFunction() error {
	ctx := context.Background()
	defer util.ShutdownFunction()

	tr.SetGlobalTracerName("ingest-cli")
	ctx, span := tr.MT().Start(ctx, "main")
	defer span.End()

	args.ConfigureFlags()
	cfg := configFromFlags()
	if err := cfg.validate(); err != nil {
		flag.Usage()
		return err
	}

	// Connect to DB via local socket, should be faster.
	config := db.NewConfig(
		mysql.WithDefaults(),
		mysql.WithEnvironment(),
		mysql.WithLocalSocket("/var/run/mysqld/mysqld.sock"),
	)
	conn, err := mysql.Connect(config)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Profiling:
	stopProfiles := func() error {
		if cfg.CpuProfile != "" || cfg.MemProfile != "" {
			fmt.Fprintln(os.Stderr, "\nStopping profiling")
		}

		if cfg.CpuProfile != "" {
			pprof.StopCPUProfile()
		}
		if cfg.MemProfile != "" {
			f, err := os.Create(cfg.MemProfile)
			if err != nil {
				return err
			}
			defer f.Close()
			if err := pprof.WriteHeapProfile(f); err != nil {
				return err
			}
		}
		return nil
	}
	defer func() {
		if err := stopProfiles(); err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
		}
	}()

	if cfg.CpuProfile != "" {
		f, err := os.Create(cfg.CpuProfile)
		if err != nil {
			return err
		}
		err = pprof.StartCPUProfile(f)
		if err != nil {
			f.Close()
			return err
		}
		defer func() {
			if err := f.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "%s\n", err)
			}
		}()
	}

	// Memprof dump if SIGUSR1.
	if cfg.DebugMemProfDump != "" {
		util.RunOnSignal(
			ctx,
			func(os.Signal) {
				if err := createMemDump(cfg.DebugMemProfDump); err != nil {
					fmt.Fprintf(os.Stderr, "%s\n", err)
				}
			},
			syscall.SIGUSR1,
		)
	}

	// Signals catching:
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sg := <-signals
		fmt.Fprintf(os.Stderr, "\nsignal caught: '%s'\n", sg.String())
		if err := stopProfiles(); err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
		}
		// Memory dump file name, if any:
		if err := createMemDump("/tmp/fpki-ingest-crash-memdump.pprof"); err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
		}
		os.Exit(1)
	}()

	return runIngest(cfg, RunDependencies{
		NewJournal: func(cfg RunConfig, jobCfg journal.JobConfiguration) (JournalStore, error) {
			return journal.NewJournal(cfg.JournalFile, jobCfg, cfg.Directory)
		},
		NewStatistics: func() *updater.Stats {
			return updater.NewStatistics(2*time.Second, printStats)
		},
		BeforeBatch: gcBeforeBatch,
		RunBatch: func(stats *updater.Stats, files []string) error {
			ctx, span := tr.MT().Start(ctx, "file-ingestion")
			defer span.End()

			proc, err := NewProcessor(
				ctx,
				conn,
				cfg.MultiInsertSize,
				stats,
				WithNumFileReaders(cfg.NumFiles),
				WithNumToChains(cfg.NumParsers),
				WithNumToCerts(cfg.NumChainToCerts),
				WithNumDBWriters(cfg.NumDBWriters),
			)
			if err != nil {
				return err
			}

			csvFiles := make([]util.CsvFile, 0, len(files))
			for _, filename := range files {
				f, err := util.LoadCsvFile(filename)
				if err != nil {
					return err
				}
				csvFiles = append(csvFiles, f)
			}
			proc.AddCsvFiles(csvFiles)
			logBatchStart(files)
			proc.Resume()
			return proc.Wait()
		},
		Coalesce: func() error {
			ctx, span := tr.MT().Start(ctx, "coalesce")
			defer span.End()
			return coalescePayloadsForDirtyDomains(ctx, conn)
		},
		UpdateSMT: func() error {
			ctx, span := tr.MT().Start(ctx, "smt-update")
			defer span.End()
			if err := updateSMT(ctx, conn); err != nil {
				return err
			}
			return cleanupDirty(ctx, conn)
		},
	})
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

func configFromFlags() RunConfig {
	return RunConfig{
		Directory:        flag.Arg(0),
		Strategy:         *args.Strategy,
		JournalFile:      *args.JournalFile,
		FileBatch:        *args.FileBatch,
		MultiInsertSize:  *args.MultiInsertSize,
		NumFiles:         *args.NumFiles,
		NumParsers:       *args.NumParsers,
		NumChainToCerts:  *args.NumChainToCerts,
		NumDBWriters:     *args.NumDBWriters,
		CpuProfile:       *args.CpuProfile,
		MemProfile:       *args.MemProfile,
		DebugMemProfDump: *args.DebugMemProfDump,
	}
}

func createMemDump(filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	err = pprof.Lookup("heap").WriteTo(f, 0) // use "heap" or "allocs"
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "\nMemory dumped to %s\n", filename)
	return nil
}
