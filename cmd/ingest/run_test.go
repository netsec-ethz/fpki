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
	"github.com/netsec-ethz/fpki/pkg/tests/testdb"
	"github.com/stretchr/testify/require"
)

const ingestTestBase = "fpki-ingest-test"

// TestRunIngestScenarios exercises the main ingest control-flow variants,
// including resume behavior, batching, follow-up phases, and cancellation.
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

// TestCompletedCTLogSize verifies that recordctsize derives the next safe CT
// index from the first canonical completed interval for the current ingest dir.
func TestCompletedCTLogSize(t *testing.T) {
	t.Run("uses_first_canonical_completed_interval_end_plus_one", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "https:__ct.googleapis.com_logs_eu1_xenon2026h1")
		cfg := newTestRunConfig(dir, filepath.Join(t.TempDir(), "journal.json"), 0, "recordctsize")

		j := loadJournalForTest(t, cfg)
		latestJobForTest(t, j).CompletedIndices = journal.CompletedIndices{
			filepath.Base(dir): {
				{Start: 0, End: 9},
				{Start: 20, End: 29},
			},
		}

		size, err := completedCTLogSize(j, dir)
		require.NoError(t, err)
		require.Equal(t, int64(10), size)
	})

	t.Run("fails_when_current_ingest_dir_has_no_completed_intervals", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "https:__ct.googleapis.com_logs_eu1_xenon2026h1")
		cfg := newTestRunConfig(dir, filepath.Join(t.TempDir(), "journal.json"), 0, "recordctsize")

		j := loadJournalForTest(t, cfg)
		latestJobForTest(t, j).CompletedIndices = journal.CompletedIndices{
			"other-log": {
				{Start: 0, End: 9},
			},
		}

		_, err := completedCTLogSize(j, dir)
		require.Error(t, err)
		require.Contains(t, err.Error(), filepath.Base(dir))
	})
}

// TestDeriveCTLogURLFromIngestDir verifies that encoded ingest-directory
// basenames are converted into canonical CT log URLs and that malformed inputs
// are rejected.
func TestDeriveCTLogURLFromIngestDir(t *testing.T) {
	testCases := map[string]struct {
		dir     string
		wantURL string
		wantErr bool
	}{
		"derives canonical url from encoded basename": {
			dir:     filepath.Join(t.TempDir(), "https:__ct.googleapis.com_logs_eu1_xenon2026h1"),
			wantURL: "https://ct.googleapis.com/logs/eu1/xenon2026h1",
		},
		"fails when derived value is not a valid url": {
			dir:     filepath.Join(t.TempDir(), "not-a-url"),
			wantErr: true,
		},
		"fails when ingest directory is empty": {
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := deriveCTLogURLFromIngestDir(tc.dir)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.wantURL, got)
		})
	}
}

// TestRunIngestRecordCTSizeUpdatesDB checks that the recordctsize strategy
// creates and later advances the persisted CT log progress row in MySQL.
func TestRunIngestRecordCTSizeUpdatesDB(t *testing.T) {
	// Prepare an isolated test DB and a cancellable context for the strategy run.
	config, removeF := testdb.ConfigureTestDB(t)
	defer removeF()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn := testdb.Connect(t, config)
	defer conn.Close()

	dirBase := "https:__ct.googleapis.com_logs_eu1_xenon2026h1"
	dir := filepath.Join(t.TempDir(), dirBase)
	cfg := newTestRunConfig(dir, filepath.Join(t.TempDir(), "journal.json"), 0, "recordctsize")

	// Seed the journal with one completed interval so recordctsize has progress
	// to translate into a persisted CT log size.
	jobCfg, err := cfg.JobConfiguration()
	require.NoError(t, err)
	j, err := journal.NewJournal(cfg.JournalFile, jobCfg, cfg.Directory)
	require.NoError(t, err)
	latestJobForTest(t, j).CompletedIndices = journal.CompletedIndices{
		dirBase: {
			{Start: 0, End: 9},
		},
	}
	require.NoError(t, j.Close())

	deps := RunDependencies{
		NewJournal: func(cfg RunConfig, jobCfg journal.JobConfiguration) (*journal.Journal, error) {
			return journal.NewJournal(cfg.JournalFile, jobCfg, cfg.Directory)
		},
		RecordCTSize: func(ctx context.Context, ctLogURL string, size int64) error {
			return conn.UpdateLastCTlogServerState(ctx, ctLogURL, size, nil)
		},
	}

	// First run should create the DB row from the initial completed interval.
	err = runIngest(ctx, cfg, deps)
	require.NoError(t, err)

	wantURL, err := deriveCTLogURLFromIngestDir(dir)
	require.NoError(t, err)
	gotSize, gotSTH, err := conn.LastCTlogServerState(ctx, wantURL)
	require.NoError(t, err)
	require.Equal(t, int64(10), gotSize)
	require.Nil(t, gotSTH)
	reopenedJournal, err := journal.NewJournal(cfg.JournalFile, jobCfg, cfg.Directory)
	require.NoError(t, err)
	require.Equal(t, int64(10), latestJobForTest(t, reopenedJournal).RecordedCTLogSize)
	require.NoError(t, reopenedJournal.Close())

	// Extend the completed coverage and rerun so the same DB row is advanced.
	reopened, err := journal.NewJournal(cfg.JournalFile, jobCfg, cfg.Directory)
	require.NoError(t, err)
	latestJobForTest(t, reopened).CompletedIndices = journal.CompletedIndices{
		dirBase: {
			{Start: 0, End: 19},
		},
	}
	require.NoError(t, reopened.Close())

	err = runIngest(ctx, cfg, deps)
	require.NoError(t, err)

	gotSize, gotSTH, err = conn.LastCTlogServerState(ctx, wantURL)
	require.NoError(t, err)
	require.Equal(t, int64(20), gotSize)
	require.Nil(t, gotSTH)
	finalJournal, err := journal.NewJournal(cfg.JournalFile, jobCfg, cfg.Directory)
	require.NoError(t, err)
	require.Equal(t, int64(20), latestJobForTest(t, finalJournal).RecordedCTLogSize)
	require.NoError(t, finalJournal.Close())
}

// makeIngestTestFiles creates a minimal bundled ingest tree with three
// sequential gzip files and returns the ingest root plus file paths in order.
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

// newTestRunConfig builds a compact RunConfig for unit tests, overriding only
// the fields that matter to the scenario under test.
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

// newTestDeps returns a dependency set that records batch execution order and
// follow-up phase counts, with optional forced failure on a chosen batch.
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

// assertErr is a sentinel error used to force controlled batch failures.
type assertErr struct{}

func (assertErr) Error() string { return "forced batch failure" }

// loadJournalForTest reopens the journal using the config's current strategy so
// tests can inspect the persisted completed-index snapshot.
func loadJournalForTest(t *testing.T, cfg RunConfig) *journal.Journal {
	t.Helper()
	jobCfg, err := cfg.JobConfiguration()
	require.NoError(t, err)
	j, err := journal.NewJournal(cfg.JournalFile, jobCfg, cfg.Directory)
	require.NoError(t, err)
	return j
}

// completedIngestTestIntervals builds the expected completed-index map for the
// synthetic ingest root created by makeIngestTestFiles.
func completedIngestTestIntervals(intervals ...journal.Interval) journal.CompletedIndices {
	return journal.CompletedIndices{
		ingestTestBase: intervals,
	}
}

// latestJobForTest returns the most recent journal job entry for in-place
// inspection or mutation within a test.
func latestJobForTest(t *testing.T, j *journal.Journal) *journal.Job {
	t.Helper()
	require.NotEmpty(t, j.Jobs)
	return &j.Jobs[len(j.Jobs)-1]
}

// previousJobForTest returns the journal entry immediately before the latest
// one, which is useful when assertions need the carried-forward prior snapshot.
func previousJobForTest(t *testing.T, j *journal.Journal) *journal.Job {
	t.Helper()
	require.GreaterOrEqual(t, len(j.Jobs), 2)
	return &j.Jobs[len(j.Jobs)-2]
}
