package main

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/netsec-ethz/fpki/cmd/ingest/journal"
	"github.com/netsec-ethz/fpki/pkg/statistics"
	"github.com/stretchr/testify/require"
)

const ingestTestBase = "fpki-ingest-test"

func TestRunIngestScenarios(t *testing.T) {
	runIngestCases := map[string]struct {
		// fileBatch controls the configured ingest batch size for the scenario.
		fileBatch int
		// strategy selects which ingest/coalesce/SMT phases the run should execute.
		strategy string
		// failBatch injects a forced RunBatch failure on the Nth batch.
		// Zero means no failure.
		failBatch int
		// missingDir swaps the generated ingest root for a path that does not exist.
		missingDir bool
		// makeContext optionally provides a custom context.
		// When nil the runner uses context.Background().
		makeContext func(*testing.T) context.Context
		// prepare mutates the test setup before runIngest is called.
		prepare func(*testing.T, RunConfig, []string)
		// check asserts the outcome using the run config, ingest files,
		// error, batch order, and phase counts.
		check func(*testing.T, RunConfig, []string, error, [][]string, int, int)
	}{
		// Starts from an empty journal and persists the full ingest interval in one run.
		"fresh_journal_persists_progress": {
			fileBatch: 0,
			strategy:  "onlyingest",
			check: func(
				t *testing.T,
				cfg RunConfig,
				files []string,
				err error,
				runOrder [][]string,
				coalesceCount int,
				updateCount int,
			) {
				require.NoError(t, err)
				require.Equal(t, [][]string{files}, runOrder)
				require.Zero(t, coalesceCount)
				require.Zero(t, updateCount)

				j := loadJournalForTest(t, cfg)
				require.Equal(t, completedIngestTestIntervals(
					journal.Interval{Start: 0, End: 29},
				), latestJobForTest(t, j).CompletedIndices)
				pending, err := j.PendingFiles()
				require.NoError(t, err)
				require.Empty(t, pending)
			},
		},
		// Reuses the previous completed snapshot so only uncovered files are ingested.
		"resume_from_existing_journal": {
			fileBatch: 1,
			strategy:  "onlyingest",
			prepare: func(t *testing.T, cfg RunConfig, files []string) {
				j := loadJournalForTest(t, cfg)
				require.NoError(t, j.CommitProgress(files[:1], false, false))
			},
			check: func(
				t *testing.T,
				cfg RunConfig,
				files []string,
				err error,
				runOrder [][]string,
				coalesceCount int,
				updateCount int,
			) {
				require.NoError(t, err)
				require.Equal(t, [][]string{{files[1]}, {files[2]}}, runOrder)
				require.Zero(t, coalesceCount)
				require.Zero(t, updateCount)

				j := loadJournalForTest(t, cfg)
				require.Equal(t, completedIngestTestIntervals(
					journal.Interval{Start: 0, End: 29},
				), latestJobForTest(t, j).CompletedIndices)
			},
		},
		// Detects a fully completed snapshot and skips ingest work entirely.
		"skip_when_already_complete": {
			fileBatch: 2,
			strategy:  "onlyingest",
			prepare: func(t *testing.T, cfg RunConfig, files []string) {
				j := loadJournalForTest(t, cfg)
				require.NoError(t, j.CommitProgress(files, false, false))
			},
			check: func(
				t *testing.T,
				_ RunConfig,
				_ []string,
				err error,
				runOrder [][]string,
				coalesceCount int,
				updateCount int,
			) {
				require.NoError(t, err)
				require.Empty(t, runOrder)
				require.Zero(t, coalesceCount)
				require.Zero(t, updateCount)
			},
		},
		// Splits ingest work into batches while preserving the discovered file order.
		"batching_respects_file_order": {
			fileBatch: 2,
			strategy:  "onlyingest",
			check: func(
				t *testing.T,
				_ RunConfig,
				files []string,
				err error,
				runOrder [][]string,
				coalesceCount int,
				updateCount int,
			) {
				require.NoError(t, err)
				require.Equal(t, [][]string{{files[0], files[1]}, {files[2]}}, runOrder)
				require.Zero(t, coalesceCount)
				require.Zero(t, updateCount)
			},
		},
		// Leaves the journal at the last successful batch when a later batch
		// fails after coalesce and SMT.
		"failed_second_batch_keeps_last_successful_progress": {
			fileBatch: 1,
			strategy:  "",
			failBatch: 2,
			check: func(
				t *testing.T,
				cfg RunConfig,
				files []string,
				err error,
				runOrder [][]string,
				coalesceCount int,
				updateCount int,
			) {
				require.Error(t, err)
				require.Len(t, runOrder, 2)
				require.Equal(t, 1, coalesceCount)
				require.Equal(t, 1, updateCount)

				j := loadJournalForTest(t, cfg)
				require.Equal(t, completedIngestTestIntervals(
					journal.Interval{Start: 0, End: 9},
				), latestJobForTest(t, j).CompletedIndices)
				require.True(t, previousJobForTest(t, j).Coalesced)
				require.True(t, previousJobForTest(t, j).UpdatedSMT)
				pending, pendingErr := j.PendingFiles()
				require.NoError(t, pendingErr)
				require.Equal(t, files[1:], pending)
			},
		},
		// Rejects malformed persisted state before any ingest work starts.
		"invalid_journal_file_returns_error": {
			fileBatch: 1,
			strategy:  "onlyingest",
			prepare: func(t *testing.T, cfg RunConfig, _ []string) {
				require.NoError(t, os.WriteFile(cfg.JournalFile, []byte("{"), 0o644))
			},
			check: func(
				t *testing.T,
				_ RunConfig,
				_ []string,
				err error,
				runOrder [][]string,
				coalesceCount int,
				updateCount int,
			) {
				require.Error(t, err)
				require.Empty(t, runOrder)
				require.Zero(t, coalesceCount)
				require.Zero(t, updateCount)
			},
		},
		// Surfaces missing ingest directories as filesystem errors without
		// running any batches.
		"missing_directory_returns_error": {
			fileBatch:  1,
			strategy:   "onlyingest",
			missingDir: true,
			check: func(
				t *testing.T,
				_ RunConfig,
				_ []string,
				err error,
				runOrder [][]string,
				coalesceCount int,
				updateCount int,
			) {
				require.Error(t, err)
				require.ErrorIs(t, err, os.ErrNotExist)
				require.Empty(t, runOrder)
				require.Zero(t, coalesceCount)
				require.Zero(t, updateCount)
			},
		},
		// Returns early when the caller-provided context is already canceled
		// before any batch starts.
		"context_canceled_before_batch": {
			fileBatch: 1,
			strategy:  "onlyingest",
			makeContext: func(t *testing.T) context.Context {
				t.Helper()
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			check: func(
				t *testing.T,
				_ RunConfig,
				_ []string,
				err error,
				runOrder [][]string,
				coalesceCount int,
				updateCount int,
			) {
				require.ErrorIs(t, err, context.Canceled)
				require.Empty(t, runOrder)
				require.Zero(t, coalesceCount)
				require.Zero(t, updateCount)
			},
		},
		// Runs the default strategy through ingest, coalesce,
		// and SMT update in one pass.
		"default_strategy_runs_all_phases": {
			fileBatch: 0,
			strategy:  "",
			check: func(
				t *testing.T,
				_ RunConfig,
				_ []string,
				err error,
				runOrder [][]string,
				coalesceCount int,
				updateCount int,
			) {
				require.NoError(t, err)
				require.Len(t, runOrder, 1)
				require.Equal(t, 1, coalesceCount)
				require.Equal(t, 1, updateCount)
			},
		},
		// Skips file ingestion and runs only coalesce plus SMT update
		// on the carried-forward snapshot.
		"skipingest_strategy_runs_followup_phases_only": {
			fileBatch: 0,
			strategy:  "skipingest",
			check: func(
				t *testing.T,
				_ RunConfig,
				_ []string,
				err error,
				runOrder [][]string,
				coalesceCount int,
				updateCount int,
			) {
				require.NoError(t, err)
				require.Empty(t, runOrder)
				require.Equal(t, 1, coalesceCount)
				require.Equal(t, 1, updateCount)
			},
		},
		// Runs only the SMT update phase when requested explicitly.
		"onlysmtupdate_strategy_runs_smt_only": {
			fileBatch: 0,
			strategy:  "onlysmtupdate",
			check: func(
				t *testing.T,
				_ RunConfig,
				_ []string,
				err error,
				runOrder [][]string,
				coalesceCount int,
				updateCount int,
			) {
				require.NoError(t, err)
				require.Empty(t, runOrder)
				require.Zero(t, coalesceCount)
				require.Equal(t, 1, updateCount)
			},
		},
	}

	for name, tc := range runIngestCases {
		t.Run(name, func(t *testing.T) {
			dir, files := makeIngestTestFiles(t)
			if tc.missingDir {
				dir = filepath.Join(t.TempDir(), "does-not-exist")
			}

			cfg := newTestRunConfig(
				dir,
				filepath.Join(t.TempDir(), "journal.json"),
				tc.fileBatch,
				tc.strategy,
			)
			if tc.prepare != nil {
				tc.prepare(t, cfg, files)
			}

			ctx := context.Background()
			if tc.makeContext != nil {
				ctx = tc.makeContext(t)
			}

			var runOrder [][]string
			var coalesceCount, updateCount int
			err := runIngest(ctx, cfg, newTestDeps(t, &runOrder, &coalesceCount, &updateCount, tc.failBatch))

			tc.check(t, cfg, files, err, runOrder, coalesceCount, updateCount)
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
		NewJournal: func(cfg RunConfig, jobCfg journal.JobConfiguration) (*journal.Journal, error) {
			return journal.NewJournal(cfg.JournalFile, jobCfg, cfg.Directory)
		},
		NewStatistics: func() *statistics.Stats {
			return statistics.NewStatistics(time.Hour, nil)
		},
		RunBatch: func(_ *statistics.Stats, files []string) error {
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

func completedIngestTestIntervals(intervals ...journal.Interval) journal.CompletedIndices {
	return journal.CompletedIndices{
		ingestTestBase: intervals,
	}
}

func latestJobForTest(t *testing.T, j *journal.Journal) journal.Job {
	t.Helper()
	require.NotEmpty(t, j.Jobs)
	return j.Jobs[len(j.Jobs)-1]
}

func previousJobForTest(t *testing.T, j *journal.Journal) journal.Job {
	t.Helper()
	require.GreaterOrEqual(t, len(j.Jobs), 2)
	return j.Jobs[len(j.Jobs)-2]
}
