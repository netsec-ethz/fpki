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

func completedIntervals(intervals ...Interval) map[string][]Interval {
	return map[string][]Interval{
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
	require.Equal(t, completedIntervals(Interval{Start: 0, End: 99999}), latestJob(t, j).CompletedIndices)
	requireJSONDoesNotContainFiles(t, journalFile)
}

// TestAddCompletedFilesIntervalScenarios verifies that completed files are
// merged into minimal intervals while preserving gaps when coverage is missing.
func TestAddCompletedFilesIntervalScenarios(t *testing.T) {
	testCases := map[string]struct {
		setupJournal  func(*Journal)
		addFiles      []string
		wantCompleted map[string][]Interval
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
					latestJob(t, j).CompletedIndices = map[string][]Interval{
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

// TestContainsCompletedInterval verifies that coverage checks succeed only when
// one stored interval fully contains the queried interval.
func TestContainsCompletedInterval(t *testing.T) {
	completed := map[string][]Interval{
		"testdata": {
			{Start: 0, End: 9},
			{Start: 20, End: 39},
		},
	}

	require.True(t, containsCompletedInterval(completed, "testdata", Interval{Start: 0, End: 9}))
	require.True(t, containsCompletedInterval(completed, "testdata", Interval{Start: 22, End: 25}))
	require.True(t, containsCompletedInterval(completed, "testdata", Interval{Start: 20, End: 39}))

	require.False(t, containsCompletedInterval(completed, "testdata", Interval{Start: 5, End: 10}))
	require.False(t, containsCompletedInterval(completed, "testdata", Interval{Start: 10, End: 19}))
	require.False(t, containsCompletedInterval(completed, "testdata", Interval{Start: 15, End: 25}))
	require.False(t, containsCompletedInterval(completed, "missing", Interval{Start: 0, End: 9}))
}

// TestPendingFilesSkipsOnlyFullyCoveredFiles verifies that partially covered
// files are still returned for processing.
func TestPendingFilesSkipsOnlyFullyCoveredFiles(t *testing.T) {
	root := makeEquivalentIngestRoot(t, "external", "partial-cover", []string{"0-9.gz", "10-19.gz", "20-29.gz"})
	journalFile := filepath.Join(t.TempDir(), "journal.json")

	j, err := NewJournal(journalFile, testJobConfig(t, false), root)
	require.NoError(t, err)
	latestJob(t, j).CompletedIndices = map[string][]Interval{
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

// TestNewJournalInvalidJSON checks that malformed journal JSON is rejected.
func TestNewJournalInvalidJSON(t *testing.T) {
	journalFile := filepath.Join(t.TempDir(), "invalid.json")
	err := os.WriteFile(journalFile, []byte("{"), 0o644)
	require.NoError(t, err)

	_, err = NewJournal(journalFile, testJobConfig(t, false), csvPath)
	require.Error(t, err)
}

// TestNewJournalReadsIntervalCompletedFilesOnRead verifies that the new
// human-readable interval encoding loads directly into in-memory intervals.
func TestNewJournalReadsIntervalCompletedFilesOnRead(t *testing.T) {
	journalFile := filepath.Join(t.TempDir(), "journal.json")
	raw := map[string]any{
		"CompletedFiles": map[string][]string{
			"testdata": {"0-99999", "200000-299999"},
		},
	}
	buf, err := json.Marshal(raw)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(journalFile, buf, 0o644))

	j, err := NewJournal(journalFile, testJobConfig(t, false), csvPath)
	require.NoError(t, err)
	require.Equal(t, completedIntervals(
		Interval{Start: 0, End: 99999},
		Interval{Start: 200000, End: 299999},
	), latestJob(t, j).CompletedIndices)
}

// TestPendingFilesEquivalentIngestRootsShareProgress verifies that equivalent
// ingest roots with the same basename share completed-file state.
func TestPendingFilesEquivalentIngestRootsShareProgress(t *testing.T) {
	firstRoot := makeEquivalentIngestRoot(t, "external", "same-log", []string{"0-9.gz", "10-19.gz"})
	secondRoot := makeEquivalentIngestRoot(t, "data", "same-log", []string{"0-9.gz", "10-19.gz", "20-29.gz"})

	journalFile := filepath.Join(t.TempDir(), "journal.json")
	j, err := NewJournal(journalFile, testJobConfig(t, false), firstRoot)
	require.NoError(t, err)
	require.NoError(t, j.CommitProgress([]string{
		filepath.Join(firstRoot, "bundled", "0-9.gz"),
		filepath.Join(firstRoot, "bundled", "10-19.gz"),
	}, false, false))

	j, err = NewJournal(journalFile, testJobConfig(t, false), secondRoot)
	require.NoError(t, err)

	got, err := j.PendingFiles()
	require.NoError(t, err)
	require.Equal(t, []string{filepath.Join(secondRoot, "bundled", "20-29.gz")}, got)
}

// TestPendingFilesDifferentIngestRootBasenamesDoNotShareProgress verifies that
// different ingest-dir basenames do not share completed-file state.
func TestPendingFilesDifferentIngestRootBasenamesDoNotShareProgress(t *testing.T) {
	firstRoot := makeEquivalentIngestRoot(t, "external", "log-a", []string{"0-9.gz"})
	secondRoot := makeEquivalentIngestRoot(t, "data", "log-b", []string{"0-9.gz"})

	journalFile := filepath.Join(t.TempDir(), "journal.json")
	j, err := NewJournal(journalFile, testJobConfig(t, false), firstRoot)
	require.NoError(t, err)
	require.NoError(t, j.CommitProgress([]string{filepath.Join(firstRoot, "bundled", "0-9.gz")}, false, false))

	j, err = NewJournal(journalFile, testJobConfig(t, false), secondRoot)
	require.NoError(t, err)

	got, err := j.PendingFiles()
	require.NoError(t, err)
	require.Equal(t, []string{filepath.Join(secondRoot, "bundled", "0-9.gz")}, got)
}

// TestCommitProgressDeduplicatesEquivalentRoots checks that adding the same
// normalized file through equivalent ingest roots remains idempotent.
func TestCommitProgressDeduplicatesEquivalentRoots(t *testing.T) {
	firstRoot := makeEquivalentIngestRoot(t, "external", "same-log", []string{"0-9.gz"})
	secondRoot := makeEquivalentIngestRoot(t, "data", "same-log", []string{"0-9.gz"})

	journalFile := filepath.Join(t.TempDir(), "journal.json")
	j, err := NewJournal(journalFile, testJobConfig(t, false), firstRoot)
	require.NoError(t, err)

	require.NoError(t, j.CommitProgress([]string{
		filepath.Join(firstRoot, "bundled", "0-9.gz"),
		filepath.Join(secondRoot, "bundled", "0-9.gz"),
	}, false, false))
	require.Equal(t, map[string][]Interval{"same-log": {{Start: 0, End: 9}}}, latestJob(t, j).CompletedIndices)
}

// TestNewJournalRejectsMalformedIntervalString verifies that reversed or
// otherwise invalid interval strings are rejected on load.
func TestNewJournalRejectsMalformedIntervalString(t *testing.T) {
	journalFile := filepath.Join(t.TempDir(), "journal.json")
	raw := map[string]any{
		"CompletedFiles": map[string][]string{
			"testdata": {"20-10"},
		},
	}
	buf, err := json.Marshal(raw)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(journalFile, buf, 0o644))

	_, err = NewJournal(journalFile, testJobConfig(t, false), csvPath)
	require.Error(t, err)
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
	require.Equal(t, completedIntervals(Interval{Start: 0, End: 99999}), latestJob(t, reopened).CompletedIndices)
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

// TestPendingFilesExcludesPlainCSVsByDefault verifies that plain `.csv` files
// stay hidden unless the run configuration opts into them.
func TestPendingFilesExcludesPlainCSVsByDefault(t *testing.T) {
	root := makeMixedIngestRoot(t)
	journalFile := filepath.Join(t.TempDir(), "journal.json")

	j, err := NewJournal(journalFile, testJobConfig(t, false), root)
	require.NoError(t, err)

	got, err := j.PendingFiles()
	require.NoError(t, err)
	require.Equal(t, []string{
		filepath.Join(root, "bundled", "0-9.gz"),
		filepath.Join(root, "bundled", "10-19.gz"),
	}, got)
}

// TestPendingFilesIncludesPlainCSVsWhenEnabled verifies that enabling the flag
// restores mixed `.gz` and `.csv` discovery.
func TestPendingFilesIncludesPlainCSVsWhenEnabled(t *testing.T) {
	root := makeMixedIngestRoot(t)
	journalFile := filepath.Join(t.TempDir(), "journal.json")

	j, err := NewJournal(journalFile, testJobConfig(t, true), root)
	require.NoError(t, err)

	got, err := j.PendingFiles()
	require.NoError(t, err)
	require.Equal(t, []string{
		filepath.Join(root, "bundled", "0-9.gz"),
		filepath.Join(root, "bundled", "10-19.gz"),
		filepath.Join(root, "20-29.csv"),
		filepath.Join(root, "30-39.csv"),
	}, got)
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

// testJobConfig returns a JobConfiguration with "onlyingest" and batch size of 2.
func testJobConfig(t *testing.T, includePlainCSVs bool) JobConfiguration {
	t.Helper()
	cfg, err := NewJobConfiguration("onlyingest", 2, includePlainCSVs)
	require.NoError(t, err)
	return cfg
}

// makeEquivalentIngestRoot creates a temporary ingest directory tree with the
// requested basename and bundled files.
func makeEquivalentIngestRoot(t *testing.T, parent string, ingestBase string, files []string) string {
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
