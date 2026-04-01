package main

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/netsec-ethz/fpki/cmd/ingest/journal"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	"github.com/netsec-ethz/fpki/pkg/util"
)

type RunConfig struct {
	Directory        string
	Strategy         string
	JournalFile      string
	FileBatch        int
	MultiInsertSize  int
	NumFiles         int
	NumParsers       int
	NumChainToCerts  int
	NumDBWriters     int
	SkipMissingFiles bool
	CpuProfile       string
	MemProfile       string
}

type JournalStore interface {
	PendingFiles() ([]string, error)
	AddCompletedFiles([]string) error
}

// RunDependencies collects all necessary functions to effectively run ingest.
type RunDependencies struct {
	NewJournal        func(RunConfig, journal.JobConfiguration) (JournalStore, error)
	NewStatistics     func() *updater.Stats
	EstimateCertCount func(string) (uint, error)
	BeforeBatch       func(batchNum, batchCount int) error
	RunBatch          func(*updater.Stats, []string) error
	Coalesce          func() error
	UpdateSMT         func() error
}

func (cfg RunConfig) JobConfiguration() (journal.JobConfiguration, error) {
	return journal.NewJobConfiguration(cfg.Strategy, cfg.FileBatch)
}

func (cfg RunConfig) validate() error {
	jobCfg, err := cfg.JobConfiguration()
	if err != nil {
		return err
	}
	if jobCfg.IngestFiles && cfg.Directory == "" {
		return fmt.Errorf("ingest requires a directory")
	}
	return nil
}

func runIngest(cfg RunConfig, deps RunDependencies) error {
	if err := cfg.validate(); err != nil {
		return err
	}

	jobCfg, err := cfg.JobConfiguration()
	if err != nil {
		return err
	}
	if deps.NewJournal == nil {
		return fmt.Errorf("missing journal dependency")
	}
	j, err := deps.NewJournal(cfg, jobCfg)
	if err != nil {
		return err
	}

	coalesce := deps.Coalesce
	if coalesce == nil {
		coalesce = func() error { return nil }
	}
	updateSMT := deps.UpdateSMT
	if updateSMT == nil {
		updateSMT = func() error { return nil }
	}

	if !jobCfg.IngestFiles {
		if jobCfg.Coalesce {
			if err := coalesce(); err != nil {
				return err
			}
		}
		if jobCfg.UpdateSMT {
			if err := updateSMT(); err != nil {
				return err
			}
		}
		return nil
	}

	if deps.NewStatistics == nil {
		return fmt.Errorf("missing statistics dependency")
	}
	if deps.RunBatch == nil {
		return fmt.Errorf("missing batch runner dependency")
	}

	stats := deps.NewStatistics()
	if stats != nil {
		defer stats.Stop()
	}

	return ingestFilesInBatches(
		j,
		stats,
		cfg.FileBatch,
		deps.EstimateCertCount,
		deps.BeforeBatch,
		func(files []string) error {
			if err := deps.RunBatch(stats, files); err != nil {
				return err
			}
			if jobCfg.Coalesce {
				if err := coalesce(); err != nil {
					return err
				}
			}
			if jobCfg.UpdateSMT {
				if err := updateSMT(); err != nil {
					return err
				}
			}
			return j.AddCompletedFiles(files)
		},
	)
}

func ingestFilesInBatches(
	j JournalStore,
	stats *updater.Stats,
	fileBatchSize int,
	estimateCertCount func(string) (uint, error),
	beforeBatch func(batchNum, batchCount int) error,
	forEachBatch func([]string) error,
) error {
	if estimateCertCount == nil {
		estimateCertCount = util.EstimateCertCount
	}

	allFilenames, err := j.PendingFiles()
	if err != nil {
		return err
	}

	if stats != nil {
		stats.TotalFiles.Store(int64(len(allFilenames)))
		stats.TotalCerts.Store(0)
		for _, fileName := range allFilenames {
			n, err := estimateCertCount(fileName)
			if err != nil {
				return err
			}
			stats.TotalCerts.Add(int64(n))
		}
	}

	if len(allFilenames) == 0 {
		return nil
	}

	if fileBatchSize <= 0 {
		fileBatchSize = len(allFilenames)
	} else {
		fileBatchSize = min(fileBatchSize, len(allFilenames))
	}
	batchCount := ((len(allFilenames) - 1) / fileBatchSize) + 1

	for i := 0; i < len(allFilenames); i += fileBatchSize {
		if beforeBatch != nil {
			if err := beforeBatch(i/fileBatchSize+1, batchCount); err != nil {
				return err
			}
		}
		s := i
		e := min(i+fileBatchSize, len(allFilenames))
		if err := forEachBatch(allFilenames[s:e]); err != nil {
			return err
		}
	}

	return nil
}

func logBatchStart(files []string) {
	names := make([]string, len(files))
	for i, f := range files {
		names[i] = filepath.Base(f)
	}
	fmt.Printf("[%s] Starting ingesting %d files : %s\n",
		time.Now().Format(time.StampMilli),
		len(files),
		strings.Join(names, ", "),
	)
}

func gcBeforeBatch(batchNum, batchCount int) error {
	var memBefore, memAfter runtime.MemStats
	runtime.ReadMemStats(&memBefore)
	runtime.GC()
	runtime.ReadMemStats(&memAfter)
	fmt.Printf("\nGC: freed %d MB\n", (memBefore.Alloc-memAfter.Alloc)/(1024*1024))
	fmt.Printf("\nProcessing File Batch %d / %d\n", batchNum, batchCount)
	return nil
}
