package journal

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Contains 3 empty files, with proper names. See below for their names.
const csvPath = "testdata/"

var csvFiles = [...]string{
	"testdata/bundled/0-99999.gz",
	"testdata/bundled/100000-199999.gz",
	"testdata/bundled/200000-299999.gz",
}

func completedIntervals(intervals ...Interval) CompletedIndices {
	return CompletedIndices{
		"testdata": intervals,
	}
}

// TestSanityOfThisTest verifies that the bundled testdata fixtures are present
// and that ListCsvFiles returns them as expected.
func TestSanityOfThisTest(t *testing.T) {
	gotGz, gotCSV, err := ListCsvFiles(csvPath)
	require.NoError(t, err)

	require.Equal(t, csvFiles[:], gotGz)
	require.Empty(t, gotCSV)

	for _, filename := range csvFiles {
		require.FileExists(t, filename)
	}
}

// TestPerformanceListCsvFiles logs the runtime and counts for a full directory
// scan, mainly as a lightweight benchmark/debug aid.
func TestPerformanceListCsvFiles(t *testing.T) {
	t0 := time.Now()
	ingestDir, err := os.Getwd()
	require.NoError(t, err)
	t.Logf("Listing files in directory %s", ingestDir)
	gzFiles, csvFiles, err := ListCsvFiles(ingestDir)
	require.NoError(t, err)
	dur := time.Since(t0)
	t.Logf("Found %d GZ and %d CSV files in %s", len(gzFiles), len(csvFiles), dur)
}

// TestNewJournal checks journal creation, reopening, and persistence of a
// newly completed interval.
func TestNewJournal(t *testing.T) {
	journalFile := filepath.Join(t.TempDir(), fmt.Sprintf("%s.json", t.Name()))

	j, err := NewJournal(journalFile, testJobConfig(t, false), "")
	require.NoError(t, err)
	require.Equal(t, journalFile, j.JournalFile)
	require.FileExists(t, journalFile)
	require.Empty(t, latestJob(t, j).CompletedIndices)
	require.NotEmpty(t, latestJob(t, j).StartTime)
	require.NotEmpty(t, latestJob(t, j).EndTime)
	require.False(t, latestJob(t, j).Coalesced)
	require.False(t, latestJob(t, j).UpdatedSMT)
	require.Equal(t, int64(-1), latestJob(t, j).UpdatedCTIndex)
	requireJSONDoesNotContainFiles(t, journalFile)

	j, err = NewJournal(journalFile, testJobConfig(t, false), "")
	require.NoError(t, err)
	require.Equal(t, journalFile, j.JournalFile)
	require.FileExists(t, journalFile)
	require.Empty(t, latestJob(t, j).CompletedIndices)
	requireJSONDoesNotContainFiles(t, journalFile)

	journalFile = filepath.Join(t.TempDir(), "with-files.json")
	j, err = NewJournal(journalFile, testJobConfig(t, false), csvPath)
	require.NoError(t, err)
	got, err := j.PendingFiles()
	require.NoError(t, err)
	require.Len(t, got, len(csvFiles))
	require.Empty(t, latestJob(t, j).CompletedIndices)
	requireJSONDoesNotContainFiles(t, journalFile)

	err = j.CommitProgress(csvFiles[:1], false, false)
	require.NoError(t, err)

	j, err = NewJournal(journalFile, testJobConfig(t, false), csvPath)
	require.NoError(t, err)
	require.Equal(
		t,
		completedIntervals(Interval{Start: 0, End: 99999}),
		latestJob(t, j).CompletedIndices,
	)
	requireJSONDoesNotContainFiles(t, journalFile)
}

// TestCommitProgressPhaseFlags verifies that the journal marks a completed
// snapshot as coalesced both after explicit coalescing and after a successful
// SMT update.
func TestCommitProgressPhaseFlags(t *testing.T) {
	testCases := map[string]struct {
		coalesced      bool
		updatedSMT     bool
		wantCoalesced  bool
		wantUpdatedSMT bool
	}{
		"coalesce_only_marks_coalesced": {
			coalesced:      true,
			updatedSMT:     false,
			wantCoalesced:  true,
			wantUpdatedSMT: false,
		},
		"smt_update_also_marks_coalesced": {
			coalesced:      false,
			updatedSMT:     true,
			wantCoalesced:  true,
			wantUpdatedSMT: true,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			journalFile := filepath.Join(
				t.TempDir(),
				fmt.Sprintf("%s.json", strings.ReplaceAll(t.Name(), "/", "-")),
			)
			j, err := NewJournal(journalFile, testJobConfig(t, false), csvPath)
			require.NoError(t, err)

			require.NoError(t, j.CommitProgress(csvFiles[:1], tc.coalesced, tc.updatedSMT))

			job := latestJob(t, j)
			require.True(t, containsCompletedInterval(
				job.CompletedIndices,
				"testdata",
				Interval{Start: 0, End: 99999},
			))
			require.Equal(t, tc.wantCoalesced, job.Coalesced)
			require.Equal(t, tc.wantUpdatedSMT, job.UpdatedSMT)
		})
	}
}

// TestJournalCarriesForwardState verifies that reopening the journal preserves
// the previous snapshot metadata when the completed indices are unchanged, and
// that extending the snapshot preserves the last CT-index update while
// invalidating coalesce and SMT state until those phases run again.
func TestJournalCarriesForwardState(t *testing.T) {
	journalFile := filepath.Join(t.TempDir(), "journal.json")

	// Seed a journal snapshot that has completed work plus all derived follow-up
	// metadata already recorded.
	j, err := NewJournal(journalFile, testJobConfig(t, false), csvPath)
	require.NoError(t, err)
	require.NoError(t, j.CommitProgress(csvFiles[:1], true, true))
	require.NoError(t, j.CommitCTIndex(100000))
	require.NoError(t, j.Close())

	// Reopening without changing the completed snapshot should carry all derived
	// metadata into the new active job.
	reopened, err := NewJournal(journalFile, testJobConfig(t, false), csvPath)
	require.NoError(t, err)
	job := latestJob(t, reopened)
	require.Equal(t, completedIntervals(Interval{Start: 0, End: 99999}), job.CompletedIndices)
	require.True(t, job.Coalesced)
	require.True(t, job.UpdatedSMT)
	require.Equal(t, int64(100000), job.UpdatedCTIndex)

	// Extending the completed snapshot invalidates coalescing and SMT state,
	// while preserving the last CT-index update value until a new DB update
	// runs.
	require.NoError(t, reopened.CommitProgress(csvFiles[1:2], false, false))

	job = latestJob(t, reopened)
	require.Equal(
		t,
		completedIntervals(
			Interval{Start: 0, End: 199999},
		),
		job.CompletedIndices,
	)
	require.False(t, job.Coalesced)
	require.False(t, job.UpdatedSMT)
	require.Equal(t, int64(100000), job.UpdatedCTIndex)
}

// TestAddCompletedFilesIntervalScenarios verifies that completed files are
// merged into minimal intervals while preserving gaps when coverage is missing.
func TestAddCompletedFilesIntervalScenarios(t *testing.T) {
	testCases := map[string]struct {
		setupJournal  func(*Journal)
		addFiles      []string
		wantCompleted CompletedIndices
		wantPending   []string
	}{
		"merges adjacent ranges": {
			addFiles: []string{csvFiles[0], csvFiles[1]},
			wantCompleted: completedIntervals(
				Interval{Start: 0, End: 199999},
			),
			wantPending: []string{csvFiles[2]},
		},
		"keeps gaps": {
			addFiles: []string{csvFiles[0], csvFiles[2]},
			wantCompleted: completedIntervals(
				Interval{Start: 0, End: 99999},
				Interval{Start: 200000, End: 299999},
			),
			wantPending: []string{csvFiles[1]},
		},
		"bridges existing intervals": {
			setupJournal: func(j *Journal) {
				latestJob(t, j).CompletedIndices = CompletedIndices{
					"testdata": {
						{Start: 0, End: 9},
						{Start: 20, End: 29},
					},
				}
			},
			addFiles: []string{
				filepath.Join(csvPath, "bundled", "10-19.gz"),
			},
			wantCompleted: completedIntervals(
				Interval{Start: 0, End: 29},
			),
			wantPending: csvFiles[:],
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			journalFile := filepath.Join(
				t.TempDir(),
				fmt.Sprintf("%s.json", strings.ReplaceAll(t.Name(), "/", "-")),
			)

			j, err := NewJournal(journalFile, testJobConfig(t, false), csvPath)
			require.NoError(t, err)

			if tc.setupJournal != nil {
				tc.setupJournal(j)
			}

			require.NoError(t, j.CommitProgress(tc.addFiles, false, false))
			require.Equal(t, tc.wantCompleted, latestJob(t, j).CompletedIndices)

			got, err := j.PendingFiles()
			require.NoError(t, err)
			require.Equal(t, tc.wantPending, got)
		})
	}
}

// TestAppendInterval exercises direct interval insertion and merging behavior
// independent of the higher-level journal APIs.
func TestAppendInterval(t *testing.T) {
	testCases := map[string]struct {
		intervals []Interval
		append    Interval
		want      []Interval
	}{
		"insert disjoint interval in order": {
			intervals: []Interval{
				{Start: 0, End: 9},
				{Start: 20, End: 29},
			},
			append: Interval{Start: 40, End: 49},
			want: []Interval{
				{Start: 0, End: 9},
				{Start: 20, End: 29},
				{Start: 40, End: 49},
			},
		},
		"merge adjacent predecessor": {
			intervals: []Interval{
				{Start: 0, End: 9},
				{Start: 20, End: 29},
			},
			append: Interval{Start: 10, End: 19},
			want: []Interval{
				{Start: 0, End: 29},
			},
		},
		"merge overlapping successor": {
			intervals: []Interval{
				{Start: 20, End: 29},
				{Start: 40, End: 49},
			},
			append: Interval{Start: 25, End: 45},
			want: []Interval{
				{Start: 20, End: 49},
			},
		},
		"insert before first interval": {
			intervals: []Interval{
				{Start: 20, End: 29},
				{Start: 40, End: 49},
			},
			append: Interval{Start: 0, End: 9},
			want: []Interval{
				{Start: 0, End: 9},
				{Start: 20, End: 29},
				{Start: 40, End: 49},
			},
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := appendInterval(tc.intervals, tc.append)

			require.Equal(t, tc.want, got)
		})
	}
}

// TestContainsCompletedIntervalScenarios verifies that coverage checks succeed
// only when one stored interval fully contains the queried interval.
func TestContainsCompletedIntervalScenarios(t *testing.T) {
	testCases := map[string]struct {
		completed     CompletedIndices
		ingestDirBase string
		query         Interval
		want          bool
	}{
		"exact_interval_hit": {
			completed: CompletedIndices{
				"testdata": {
					{Start: 0, End: 9},
					{Start: 20, End: 39},
				},
			},
			ingestDirBase: "testdata",
			query:         Interval{Start: 0, End: 9},
			want:          true,
		},
		"contained_sub_range": {
			completed: CompletedIndices{
				"testdata": {
					{Start: 0, End: 9},
					{Start: 20, End: 39},
				},
			},
			ingestDirBase: "testdata",
			query:         Interval{Start: 22, End: 25},
			want:          true,
		},
		"second_interval_exact_hit": {
			completed: CompletedIndices{
				"testdata": {
					{Start: 0, End: 9},
					{Start: 20, End: 39},
				},
			},
			ingestDirBase: "testdata",
			query:         Interval{Start: 20, End: 39},
			want:          true,
		},
		"overlaps_end_without_full_coverage": {
			completed: CompletedIndices{
				"testdata": {
					{Start: 0, End: 9},
					{Start: 20, End: 39},
				},
			},
			ingestDirBase: "testdata",
			query:         Interval{Start: 5, End: 10},
			want:          false,
		},
		"gap_interval": {
			completed: CompletedIndices{
				"testdata": {
					{Start: 0, End: 9},
					{Start: 20, End: 39},
				},
			},
			ingestDirBase: "testdata",
			query:         Interval{Start: 10, End: 19},
			want:          false,
		},
		"spanning_two_intervals": {
			completed: CompletedIndices{
				"testdata": {
					{Start: 0, End: 9},
					{Start: 20, End: 39},
				},
			},
			ingestDirBase: "testdata",
			query:         Interval{Start: 15, End: 25},
			want:          false,
		},
		"missing_ingest_root": {
			completed: CompletedIndices{
				"testdata": {
					{Start: 0, End: 9},
					{Start: 20, End: 39},
				},
			},
			ingestDirBase: "missing",
			query:         Interval{Start: 0, End: 9},
			want:          false,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := containsCompletedInterval(tc.completed, tc.ingestDirBase, tc.query)

			require.Equal(t, tc.want, got)
		})
	}
}

// TestPendingFilesSkipsOnlyFullyCoveredFiles verifies that partially covered
// files are still returned for processing.
func TestPendingFilesSkipsOnlyFullyCoveredFiles(t *testing.T) {
	root := makeEquivalentIngestRoot(
		t,
		"external",
		"partial-cover",
		[]string{"0-9.gz", "10-19.gz", "20-29.gz"},
	)
	journalFile := filepath.Join(t.TempDir(), "journal.json")

	j, err := NewJournal(journalFile, testJobConfig(t, false), root)
	require.NoError(t, err)
	latestJob(t, j).CompletedIndices = CompletedIndices{
		"partial-cover": {
			{Start: 0, End: 8},
			{Start: 20, End: 29},
		},
	}

	got, err := j.PendingFiles()
	require.NoError(t, err)
	require.Equal(t, []string{
		filepath.Join(root, "bundled", "0-9.gz"),
		filepath.Join(root, "bundled", "10-19.gz"),
	}, got)
}

// TestNewJournalReadScenarios verifies that current-format JSON is either read
// successfully or rejected when malformed.
func TestNewJournalReadScenarios(t *testing.T) {
	testCases := map[string]struct {
		rawJSON       []byte
		ingestDir     string
		wantErr       bool
		wantCompleted CompletedIndices
	}{
		"malformed_json_bytes": {
			rawJSON:   []byte("{"),
			ingestDir: csvPath,
			wantErr:   true,
		},
		"valid_job_with_two_completed_intervals": {
			rawJSON: mustMarshalJSON(t, map[string]any{
				"Jobs": []map[string]any{
					{
						"Cwd":              "/tmp",
						"Cmd":              []string{"ingest"},
						"JobConfiguration": testJobConfig(t, false),
						"StartTime":        "2026-04-08T12:00:00Z",
						"EndTime":          "2026-04-08T12:00:00Z",
						"CompletedIndices": map[string][]string{
							"testdata": {"0-99999", "200000-299999"},
						},
					},
				},
			}),
			ingestDir: csvPath,
			wantCompleted: completedIntervals(
				Interval{Start: 0, End: 99999},
				Interval{Start: 200000, End: 299999},
			),
		},
		"valid_job_with_malformed_interval_string": {
			rawJSON: mustMarshalJSON(t, map[string]any{
				"Jobs": []map[string]any{
					{
						"Cwd":              "/tmp",
						"Cmd":              []string{"ingest"},
						"JobConfiguration": testJobConfig(t, false),
						"StartTime":        "2026-04-08T12:00:00Z",
						"EndTime":          "2026-04-08T12:00:00Z",
						"CompletedIndices": map[string][]string{
							"testdata": {"20-10"},
						},
					},
				},
			}),
			ingestDir: csvPath,
			wantErr:   true,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			journalFile := filepath.Join(t.TempDir(), "journal.json")
			require.NoError(t, os.WriteFile(journalFile, tc.rawJSON, 0o644))

			j, err := NewJournal(journalFile, testJobConfig(t, false), tc.ingestDir)
			if tc.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.wantCompleted, latestJob(t, j).CompletedIndices)
		})
	}
}

// TestEquivalentIngestRootProgressScenarios verifies basename-based progress
// sharing and equivalent-root deduplication behavior.
func TestEquivalentIngestRootProgressScenarios(t *testing.T) {
	testCases := map[string]struct {
		firstBase      string
		secondBase     string
		firstFiles     []string
		secondFiles    []string
		commitFiles    func(firstRoot, secondRoot string) []string
		reopenOnSecond bool
		wantPending    []string
		wantCompleted  CompletedIndices
	}{
		"same_basename_shares_progress_across_reopen": {
			firstBase:   "same-log",
			secondBase:  "same-log",
			firstFiles:  []string{"0-9.gz", "10-19.gz"},
			secondFiles: []string{"0-9.gz", "10-19.gz", "20-29.gz"},
			commitFiles: func(firstRoot, _ string) []string {
				return []string{
					filepath.Join(firstRoot, "bundled", "0-9.gz"),
					filepath.Join(firstRoot, "bundled", "10-19.gz"),
				}
			},
			reopenOnSecond: true,
			wantPending: []string{
				filepath.Join("ROOT", "bundled", "20-29.gz"),
			},
		},
		"different_basenames_do_not_share_progress": {
			firstBase:   "log-a",
			secondBase:  "log-b",
			firstFiles:  []string{"0-9.gz"},
			secondFiles: []string{"0-9.gz"},
			commitFiles: func(firstRoot, _ string) []string {
				return []string{
					filepath.Join(firstRoot, "bundled", "0-9.gz"),
				}
			},
			reopenOnSecond: true,
			wantPending: []string{
				filepath.Join("ROOT", "bundled", "0-9.gz"),
			},
		},
		"duplicate_commit_from_equivalent_roots_stays_deduplicated": {
			firstBase:   "same-log",
			secondBase:  "same-log",
			firstFiles:  []string{"0-9.gz"},
			secondFiles: []string{"0-9.gz"},
			commitFiles: func(firstRoot, secondRoot string) []string {
				return []string{
					filepath.Join(firstRoot, "bundled", "0-9.gz"),
					filepath.Join(secondRoot, "bundled", "0-9.gz"),
				}
			},
			wantCompleted: CompletedIndices{
				"same-log": {{Start: 0, End: 9}},
			},
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			firstRoot := makeEquivalentIngestRoot(t, "external", tc.firstBase, tc.firstFiles)
			secondRoot := makeEquivalentIngestRoot(t, "data", tc.secondBase, tc.secondFiles)

			journalFile := filepath.Join(t.TempDir(), "journal.json")
			j, err := NewJournal(journalFile, testJobConfig(t, false), firstRoot)
			require.NoError(t, err)

			require.NoError(
				t,
				j.CommitProgress(tc.commitFiles(firstRoot, secondRoot), false, false),
			)

			if tc.wantCompleted != nil {
				require.Equal(t, tc.wantCompleted, latestJob(t, j).CompletedIndices)
			}

			if !tc.reopenOnSecond {
				return
			}

			j, err = NewJournal(journalFile, testJobConfig(t, false), secondRoot)
			require.NoError(t, err)

			got, err := j.PendingFiles()
			require.NoError(t, err)
			require.Equal(t, replaceRootPlaceholder(tc.wantPending, secondRoot), got)
		})
	}
}

// TestClosePersistsAndIsIdempotent verifies that Close flushes state and can be
// called multiple times safely.
func TestClosePersistsAndIsIdempotent(t *testing.T) {
	journalFile := filepath.Join(t.TempDir(), "journal.json")
	j, err := NewJournal(journalFile, testJobConfig(t, false), csvPath)
	require.NoError(t, err)

	addCompletedInterval(latestJob(t, j).CompletedIndices, "testdata", Interval{Start: 0, End: 99999})

	require.NoError(t, j.Close())
	require.NoError(t, j.Close())

	reopened, err := NewJournal(journalFile, testJobConfig(t, false), csvPath)
	require.NoError(t, err)
	require.Equal(
		t,
		completedIntervals(Interval{Start: 0, End: 99999}),
		latestJob(t, reopened).CompletedIndices,
	)
}

// TestPendingFilesUsesFreshDirectoryListing verifies that PendingFiles always
// reflects the current filesystem contents rather than a cached listing.
func TestPendingFilesUsesFreshDirectoryListing(t *testing.T) {
	root := t.TempDir()
	bundledDir := filepath.Join(root, "bundled")
	require.NoError(t, os.MkdirAll(bundledDir, 0o755))

	firstFile := filepath.Join(bundledDir, "0-9.gz")
	require.NoError(t, os.WriteFile(firstFile, nil, 0o644))

	journalFile := filepath.Join(t.TempDir(), "journal.json")
	j, err := NewJournal(journalFile, testJobConfig(t, false), root)
	require.NoError(t, err)

	got, err := j.PendingFiles()
	require.NoError(t, err)
	require.Equal(t, []string{firstFile}, got)

	secondFile := filepath.Join(bundledDir, "10-19.gz")
	require.NoError(t, os.WriteFile(secondFile, nil, 0o644))

	got, err = j.PendingFiles()
	require.NoError(t, err)
	require.Equal(t, []string{firstFile, secondFile}, got)
}

// TestPendingFilesPlainCSVScenarios verifies that plain CSV discovery follows
// the IncludePlainCSVs configuration.
func TestPendingFilesPlainCSVScenarios(t *testing.T) {
	testCases := map[string]struct {
		includePlainCSVs bool
		want             []string
	}{
		"plain_csvs_excluded_by_default": {
			want: []string{
				filepath.Join("ROOT", "bundled", "0-9.gz"),
				filepath.Join("ROOT", "bundled", "10-19.gz"),
			},
		},
		"plain_csvs_included_when_enabled": {
			includePlainCSVs: true,
			want: []string{
				filepath.Join("ROOT", "bundled", "0-9.gz"),
				filepath.Join("ROOT", "bundled", "10-19.gz"),
				filepath.Join("ROOT", "20-29.csv"),
				filepath.Join("ROOT", "30-39.csv"),
			},
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			root := makeMixedIngestRoot(t)
			journalFile := filepath.Join(t.TempDir(), "journal.json")

			j, err := NewJournal(journalFile, testJobConfig(t, tc.includePlainCSVs), root)
			require.NoError(t, err)

			got, err := j.PendingFiles()
			require.NoError(t, err)
			require.Equal(t, replaceRootPlaceholder(tc.want, root), got)
		})
	}
}

// requireJSONDoesNotContainFiles asserts that the journal JSON does not use the
// long-removed Files field.
func requireJSONDoesNotContainFiles(t *testing.T, journalFile string) {
	t.Helper()
	buf, err := os.ReadFile(journalFile)
	require.NoError(t, err)
	require.NotContains(t, string(buf), "\"Files\"")
	require.NotContains(t, string(buf), "\"CompletedFiles\"")
}

func latestJob(t *testing.T, j *Journal) *Job {
	t.Helper()
	require.NotEmpty(t, j.Jobs)
	return &j.Jobs[len(j.Jobs)-1]
}

func mustMarshalJSON(t *testing.T, value any) []byte {
	t.Helper()
	buf, err := json.Marshal(value)
	require.NoError(t, err)
	return buf
}

func replaceRootPlaceholder(paths []string, root string) []string {
	replaced := make([]string, len(paths))
	for i, path := range paths {
		replaced[i] = strings.Replace(path, "ROOT", root, 1)
	}
	return replaced
}

// testJobConfig returns a JobConfiguration with "onlyingest" and batch size of 2.
func testJobConfig(t *testing.T, includePlainCSVs bool) JobConfiguration {
	t.Helper()
	cfg, err := NewJobConfiguration("onlyingest", 2, includePlainCSVs)
	require.NoError(t, err)
	return cfg
}

// makeEquivalentIngestRoot creates a temporary ingest directory tree with the
// requested basename and bundled files.
func makeEquivalentIngestRoot(
	t *testing.T,
	parent string,
	ingestBase string,
	files []string,
) string {
	t.Helper()

	root := filepath.Join(t.TempDir(), parent, ingestBase)
	bundledDir := filepath.Join(root, "bundled")
	require.NoError(t, os.MkdirAll(bundledDir, 0o755))
	for _, name := range files {
		require.NoError(t, os.WriteFile(filepath.Join(bundledDir, name), nil, 0o644))
	}
	return root
}

// makeMixedIngestRoot creates an ingest directory containing both bundled `.gz`
// files and top-level plain `.csv` files.
func makeMixedIngestRoot(t *testing.T) string {
	t.Helper()

	root := t.TempDir()
	bundledDir := filepath.Join(root, "bundled")
	require.NoError(t, os.MkdirAll(bundledDir, 0o755))
	for _, name := range []string{"0-9.gz", "10-19.gz"} {
		require.NoError(t, os.WriteFile(filepath.Join(bundledDir, name), nil, 0o644))
	}
	for _, name := range []string{"20-29.csv", "30-39.csv"} {
		require.NoError(t, os.WriteFile(filepath.Join(root, name), nil, 0o644))
	}
	return root
}
