package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/netsec-ethz/fpki/cmd/ingest/journal"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	"github.com/stretchr/testify/require"
)

const ingestTestBase = "fpki-ingest-test"

func TestRunIngestFreshJournalPersistsProgress(t *testing.T) {
	dir, files := makeIngestTestFiles(t)
	cfg := newTestRunConfig(dir, filepath.Join(t.TempDir(), "journal.json"), 0, "onlyingest")

	var runOrder [][]string
	var coalesceCount, updateCount int
	err := runIngest(cfg, newTestDeps(t, &runOrder, &coalesceCount, &updateCount, 0))
	require.NoError(t, err)

	require.Equal(t, [][]string{files}, runOrder)
	require.Zero(t, coalesceCount)
	require.Zero(t, updateCount)

	j := loadJournalForTest(t, cfg)
	require.Equal(t, []string{
		filepath.Join(ingestTestBase, "0-9.gz"),
		filepath.Join(ingestTestBase, "10-19.gz"),
		filepath.Join(ingestTestBase, "20-29.gz"),
	}, j.CompletedFiles)
	pending, err := j.PendingFiles()
	require.NoError(t, err)
	require.Empty(t, pending)
}

func TestRunIngestResumesFromExistingJournal(t *testing.T) {
	dir, files := makeIngestTestFiles(t)
	cfg := newTestRunConfig(dir, filepath.Join(t.TempDir(), "journal.json"), 1, "onlyingest")

	j := loadJournalForTest(t, cfg)
	require.NoError(t, j.AddCompletedFiles(files[:1]))

	var runOrder [][]string
	var coalesceCount, updateCount int
	err := runIngest(cfg, newTestDeps(t, &runOrder, &coalesceCount, &updateCount, 0))
	require.NoError(t, err)

	require.Equal(t, [][]string{{files[1]}, {files[2]}}, runOrder)

	j = loadJournalForTest(t, cfg)
	require.Equal(t, []string{
		filepath.Join(ingestTestBase, "0-9.gz"),
		filepath.Join(ingestTestBase, "10-19.gz"),
		filepath.Join(ingestTestBase, "20-29.gz"),
	}, j.CompletedFiles)
}

func TestRunIngestSkipsWhenAlreadyComplete(t *testing.T) {
	dir, files := makeIngestTestFiles(t)
	cfg := newTestRunConfig(dir, filepath.Join(t.TempDir(), "journal.json"), 2, "onlyingest")

	j := loadJournalForTest(t, cfg)
	require.NoError(t, j.AddCompletedFiles(files))

	var runOrder [][]string
	var coalesceCount, updateCount int
	err := runIngest(cfg, newTestDeps(t, &runOrder, &coalesceCount, &updateCount, 0))
	require.NoError(t, err)
	require.Empty(t, runOrder)
}

func TestRunIngestBatchingOrder(t *testing.T) {
	dir, files := makeIngestTestFiles(t)
	cfg := newTestRunConfig(dir, filepath.Join(t.TempDir(), "journal.json"), 2, "onlyingest")

	var runOrder [][]string
	var coalesceCount, updateCount int
	err := runIngest(cfg, newTestDeps(t, &runOrder, &coalesceCount, &updateCount, 0))
	require.NoError(t, err)
	require.Equal(t, [][]string{{files[0], files[1]}, {files[2]}}, runOrder)
}

func TestRunIngestFailedBatchDoesNotAdvanceJournal(t *testing.T) {
	dir, files := makeIngestTestFiles(t)
	cfg := newTestRunConfig(dir, filepath.Join(t.TempDir(), "journal.json"), 1, "")

	var runOrder [][]string
	var coalesceCount, updateCount int
	err := runIngest(cfg, newTestDeps(t, &runOrder, &coalesceCount, &updateCount, 2))
	require.Error(t, err)
	require.Len(t, runOrder, 2)
	require.Equal(t, 1, coalesceCount)
	require.Equal(t, 1, updateCount)

	j := loadJournalForTest(t, cfg)
	require.Equal(t, []string{filepath.Join(ingestTestBase, "0-9.gz")}, j.CompletedFiles)
	pending, err := j.PendingFiles()
	require.NoError(t, err)
	require.Equal(t, files[1:], pending)
}

func TestRunIngestInvalidJournalFileReturnsError(t *testing.T) {
	dir, _ := makeIngestTestFiles(t)
	journalFile := filepath.Join(t.TempDir(), "journal.json")
	require.NoError(t, os.WriteFile(journalFile, []byte("{"), 0o644))
	cfg := newTestRunConfig(dir, journalFile, 1, "onlyingest")

	var runOrder [][]string
	var coalesceCount, updateCount int
	err := runIngest(cfg, newTestDeps(t, &runOrder, &coalesceCount, &updateCount, 0))
	require.Error(t, err)
}

func TestRunIngestMissingDirectoryReturnsError(t *testing.T) {
	cfg := newTestRunConfig(
		filepath.Join(t.TempDir(), "does-not-exist"),
		filepath.Join(t.TempDir(), "journal.json"),
		1,
		"onlyingest",
	)

	var runOrder [][]string
	var coalesceCount, updateCount int
	err := runIngest(cfg, newTestDeps(t, &runOrder, &coalesceCount, &updateCount, 0))
	require.Error(t, err)
	require.ErrorIs(t, err, os.ErrNotExist)
	require.Empty(t, runOrder)
}

func TestRunIngestStrategyMatrix(t *testing.T) {
	testCases := map[string]struct {
		strategy      string
		wantBatches   int
		wantCoalesce  int
		wantSMTUpdate int
	}{
		"onlyingest":    {strategy: "onlyingest", wantBatches: 1},
		"default":       {strategy: "", wantBatches: 1, wantCoalesce: 1, wantSMTUpdate: 1},
		"skipingest":    {strategy: "skipingest", wantCoalesce: 1, wantSMTUpdate: 1},
		"onlysmtupdate": {strategy: "onlysmtupdate", wantSMTUpdate: 1},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			dir, _ := makeIngestTestFiles(t)
			cfg := newTestRunConfig(dir, filepath.Join(t.TempDir(), "journal.json"), 0, tc.strategy)

			var runOrder [][]string
			var coalesceCount, updateCount int
			err := runIngest(cfg, newTestDeps(t, &runOrder, &coalesceCount, &updateCount, 0))
			require.NoError(t, err)
			require.Len(t, runOrder, tc.wantBatches)
			require.Equal(t, tc.wantCoalesce, coalesceCount)
			require.Equal(t, tc.wantSMTUpdate, updateCount)
		})
	}
}

func makeIngestTestFiles(t *testing.T) (string, []string) {
	t.Helper()

	root := t.TempDir()
	root = filepath.Join(root, ingestTestBase)
	bundledDir := filepath.Join(root, "bundled")
	require.NoError(t, os.MkdirAll(bundledDir, 0o755))

	files := []string{
		filepath.Join(bundledDir, "0-9.gz"),
		filepath.Join(bundledDir, "10-19.gz"),
		filepath.Join(bundledDir, "20-29.gz"),
	}
	for _, name := range files {
		require.NoError(t, os.WriteFile(name, nil, 0o644))
	}
	return root, files
}

func newTestRunConfig(dir string, journalFile string, fileBatch int, strategy string) RunConfig {
	return RunConfig{
		Directory:    dir,
		JournalFile:  journalFile,
		FileBatch:    fileBatch,
		Strategy:     strategy,
		NumFiles:     1,
		NumParsers:   1,
		NumDBWriters: 1,
	}
}

func newTestDeps(
	t *testing.T,
	runOrder *[][]string,
	coalesceCount *int,
	updateCount *int,
	failBatch int,
) RunDependencies {
	t.Helper()

	return RunDependencies{
		NewJournal: func(cfg RunConfig, jobCfg journal.JobConfiguration) (JournalStore, error) {
			return journal.NewJournal(cfg.JournalFile, jobCfg, cfg.Directory)
		},
		NewStatistics: func() *updater.Stats {
			return updater.NewStatistics(time.Hour, nil)
		},
		RunBatch: func(_ *updater.Stats, files []string) error {
			*runOrder = append(*runOrder, slices.Clone(files))
			if failBatch > 0 && len(*runOrder) == failBatch {
				return assertErr{}
			}
			return nil
		},
		Coalesce: func() error {
			*coalesceCount = *coalesceCount + 1
			return nil
		},
		UpdateSMT: func() error {
			*updateCount = *updateCount + 1
			return nil
		},
	}
}

type assertErr struct{}

func (assertErr) Error() string { return "forced batch failure" }

func loadJournalForTest(t *testing.T, cfg RunConfig) *journal.Journal {
	t.Helper()
	jobCfg, err := cfg.JobConfiguration()
	require.NoError(t, err)
	j, err := journal.NewJournal(cfg.JournalFile, jobCfg, cfg.Directory)
	require.NoError(t, err)
	return j
}
