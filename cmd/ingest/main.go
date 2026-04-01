package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
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

	// Diagnostics and signal catching.
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGUSR1)
	go func() {
		for sg := range signals {
			fmt.Fprintf(os.Stderr, "\n%s: signal caught: '%s'\n", time.Now().String(), sg.String())
			if sg == syscall.SIGINT || sg == syscall.SIGTERM {
				if err := stopProfiles(); err != nil {
					fmt.Fprintf(os.Stderr, "%s\n", err)
				}
			}
			dir, err := createDiagnosticsBundle(cfg, sg, os.Stderr)
			if dir != "" {
				fmt.Fprintf(os.Stderr, "\nDiagnostics dumped to %s\n", dir)
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s\n", err)
			}
			if sg == syscall.SIGINT || sg == syscall.SIGTERM {
				os.Exit(1)
			}
		}
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
				WithSkipMissingFiles(cfg.SkipMissingFiles),
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
		SkipMissingFiles: *args.SkipMissingFiles,
		CpuProfile:       *args.CpuProfile,
		MemProfile:       *args.MemProfile,
	}
}

var diagnosticsRootDir = os.TempDir()
var diagnosticsNow = time.Now
var diagnosticsProcessStart = time.Now()

type diagnosticsWriter struct {
	createDir        func() (string, error)
	writeHeap        func(string) error
	writeHeapAfterGC func(string) error
	writeAllocs      func(string) error
	writeGoroutines  func(string) error
	writeMemStats    func(string) error
	writeMeta        func(string, diagnosticsMeta) error
}

type diagnosticsMeta struct {
	Signal       string
	Time         time.Time
	ProcessStart time.Time
	Uptime       time.Duration
	PID          int
	Args         []string
	Config       RunConfig
}

func createDiagnosticsBundle(cfg RunConfig, sg os.Signal, stderr io.Writer) (string, error) {
	return createDiagnosticsBundleWithWriter(cfg, sg, stderr, newDefaultDiagnosticsWriter())
}

func createDiagnosticsBundleWithWriter(
	cfg RunConfig,
	sg os.Signal,
	stderr io.Writer,
	writer diagnosticsWriter,
) (string, error) {
	dir, err := writer.createDir()
	if err != nil {
		return "", err
	}
	captureTime := diagnosticsNow()

	meta := diagnosticsMeta{
		Signal:       signalName(sg),
		Time:         captureTime,
		ProcessStart: diagnosticsProcessStart,
		Uptime:       captureTime.Sub(diagnosticsProcessStart),
		PID:          os.Getpid(),
		Args:         append([]string(nil), os.Args...),
		Config:       cfg,
	}

	var errs []error
	writeFile := func(name string, fn func(string) error) {
		path := filepath.Join(dir, name)
		if err := fn(path); err != nil {
			err = fmt.Errorf("writing %s: %w", name, err)
			errs = append(errs, err)
			fmt.Fprintf(stderr, "%s\n", err)
		}
	}

	writeFile("heap.pprof", writer.writeHeap)
	writeFile("allocs.pprof", writer.writeAllocs)
	writeFile("goroutines.txt", writer.writeGoroutines)
	writeFile("memstats.txt", writer.writeMemStats)
	writeFile("heap-after-gc.pprof", writer.writeHeapAfterGC)
	writeFile("meta.txt", func(path string) error {
		return writer.writeMeta(path, meta)
	})

	return dir, errors.Join(errs...)
}

func newDefaultDiagnosticsWriter() diagnosticsWriter {
	return diagnosticsWriter{
		createDir:        createDiagnosticsDir,
		writeHeap:        func(path string) error { return writeProfile(path, "heap", 0, false) },
		writeHeapAfterGC: func(path string) error { return writeProfile(path, "heap", 0, true) },
		writeAllocs:      func(path string) error { return writeProfile(path, "allocs", 0, false) },
		writeGoroutines:  func(path string) error { return writeProfile(path, "goroutine", 2, false) },
		writeMemStats:    writeMemStatsFile,
		writeMeta:        writeMetaFile,
	}
}

func createDiagnosticsDir() (string, error) {
	for range 16 {
		dir := filepath.Join(
			diagnosticsRootDir,
			fmt.Sprintf("fpki-diagnostics-%s", diagnosticsNow().Format("20060102-150405.000")),
		)
		err := os.Mkdir(dir, 0o755)
		if err == nil {
			return dir, nil
		}
		if os.IsExist(err) {
			time.Sleep(time.Millisecond)
			continue
		}
		return "", err
	}
	return "", fmt.Errorf("failed to create diagnostics directory after multiple attempts")
}

func writeProfile(path, name string, debug int, forceGC bool) error {
	if forceGC {
		runtime.GC()
	}
	prof := pprof.Lookup(name)
	if prof == nil {
		return fmt.Errorf("pprof profile %q is unavailable", name)
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return prof.WriteTo(f, debug)
}

func writeMemStatsFile(path string) error {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = fmt.Fprintf(f,
		"Alloc=%d\nHeapAlloc=%d\nHeapInuse=%d\nHeapIdle=%d\nHeapReleased=%d\nSys=%d\nNumGC=%d\n"+
			"NextGC=%d\nGCCPUFraction=%f\n",
		stats.Alloc,
		stats.HeapAlloc,
		stats.HeapInuse,
		stats.HeapIdle,
		stats.HeapReleased,
		stats.Sys,
		stats.NumGC,
		stats.NextGC,
		stats.GCCPUFraction,
	)
	return err
}

func writeMetaFile(path string, meta diagnosticsMeta) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = fmt.Fprintf(f,
		"timestamp=%s\nprocess_start=%s\nuptime=%s\nuptime_seconds=%f\nsignal=%s\npid=%d\nargs=%q\n"+
			"strategy=%s\nfilebatch=%d\nmultiinsert=%d\nnumfiles=%d\nnumparsers=%d\nnumdechainers=%d\n"+
			"numdbworkers=%d\ndirectory=%s\njournal=%s\n",
		meta.Time.Format(time.RFC3339Nano),
		meta.ProcessStart.Format(time.RFC3339Nano),
		meta.Uptime,
		meta.Uptime.Seconds(),
		meta.Signal,
		meta.PID,
		meta.Args,
		meta.Config.Strategy,
		meta.Config.FileBatch,
		meta.Config.MultiInsertSize,
		meta.Config.NumFiles,
		meta.Config.NumParsers,
		meta.Config.NumChainToCerts,
		meta.Config.NumDBWriters,
		meta.Config.Directory,
		meta.Config.JournalFile,
	)
	return err
}

func signalName(sg os.Signal) string {
	if sg == nil {
		return "unknown"
	}
	return sg.String()
}
