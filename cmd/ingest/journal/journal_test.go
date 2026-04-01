package journal

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

var normalizedCSVFiles = [...]string{
	"testdata/0-99999.gz",
	"testdata/100000-199999.gz",
	"testdata/200000-299999.gz",
}

func normalizedCSVSet(indices ...int) map[string]map[string]struct{} {
	files := map[string]map[string]struct{}{}
	for _, i := range indices {
		addCompletedFile(files, "testdata", filepath.Base(normalizedCSVFiles[i]))
	}
	return files
}

// TestSanityOfThisTest verifies that the content of the testdata/bundled directory is as expected.
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

// TestPerformanceListCsvFiles is used mainly in the production server, to assess how long
// it takes to list a directory. Typically used when the working directory is the USB.
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
// newly completed file.
func TestNewJournal(t *testing.T) {
	journalFile := filepath.Join(t.TempDir(), fmt.Sprintf("%s.json", t.Name()))

	j, err := NewJournal(journalFile, testJobConfig(t), "")
	require.NoError(t, err)
	require.Equal(t, journalFile, j.JournalFile)
	require.FileExists(t, journalFile)
	require.Empty(t, j.CompletedFiles)
	requireJSONDoesNotContainFiles(t, journalFile)

	// Recreate.
	j, err = NewJournal(journalFile, testJobConfig(t), "")
	require.NoError(t, err)
	require.Equal(t, journalFile, j.JournalFile)
	require.FileExists(t, journalFile)
	require.Empty(t, j.CompletedFiles)
	requireJSONDoesNotContainFiles(t, journalFile)

	// Recreate, with existing non-processed files.
	journalFile = filepath.Join(t.TempDir(), "with-files.json")
	j, err = NewJournal(journalFile, testJobConfig(t), csvPath)
	require.NoError(t, err)
	got, err := j.PendingFiles()
	require.NoError(t, err)
	require.Len(t, got, len(csvFiles))
	require.Empty(t, j.CompletedFiles)
	requireJSONDoesNotContainFiles(t, journalFile)

	// Add one file as completed.
	err = j.AddCompletedFiles(csvFiles[:1])
	require.NoError(t, err)
	// Check that the completed file is there.
	j, err = NewJournal(journalFile, testJobConfig(t), csvPath)
	require.NoError(t, err)
	require.Equal(t, normalizedCSVSet(0), j.CompletedFiles)
	requireJSONDoesNotContainFiles(t, journalFile)
}

// TestAddCompletedFiles checks that AddCompletedFiles correctly adds the file names,
// and that the nested set is kept deduplicated.
func TestAddCompletedFiles(t *testing.T) {
	journalFile := filepath.Join(t.TempDir(), fmt.Sprintf("%s.json", t.Name()))

	j, err := NewJournal(journalFile, testJobConfig(t), csvPath)
	require.NoError(t, err)

	got, err := j.PendingFiles()
	require.NoError(t, err)
	require.Equal(t, csvFiles[:], got)

	// Add the first file 0-99999.
	err = j.AddCompletedFiles(csvFiles[0:1])
	require.NoError(t, err)
	require.Equal(t, normalizedCSVSet(0), j.CompletedFiles)
	got, err = j.PendingFiles()
	require.NoError(t, err)
	require.Equal(t, []string{csvFiles[1], csvFiles[2]}, got)

	// Add the last file 200000-299999.
	err = j.AddCompletedFiles(csvFiles[2:3])
	require.NoError(t, err)
	got, err = j.PendingFiles()
	require.NoError(t, err)
	require.Equal(t, []string{csvFiles[1]}, got)
	require.Len(t, got, 1)
	// Check that indeed the pending file is the second from csvFiles 100000-199999.
	require.Equal(t, csvFiles[1], got[0])
}

// TestPendingFiles verifies that completed files are excluded from the pending
// file list.
func TestPendingFiles(t *testing.T) {
	journalFile := filepath.Join(t.TempDir(), fmt.Sprintf("%s.json", t.Name()))

	j, err := NewJournal(journalFile, testJobConfig(t), csvPath)
	require.NoError(t, err)

	err = j.AddCompletedFiles([]string{csvFiles[0], csvFiles[2]})
	require.NoError(t, err)

	got, err := j.PendingFiles()
	require.NoError(t, err)
	require.Equal(t, []string{csvFiles[1]}, got)
}

// TestNewJournalInvalidJSON checks that malformed journal JSON is rejected.
func TestNewJournalInvalidJSON(t *testing.T) {
	journalFile := filepath.Join(t.TempDir(), "invalid.json")
	err := os.WriteFile(journalFile, []byte("{"), 0o644)
	require.NoError(t, err)

	_, err = NewJournal(journalFile, testJobConfig(t), csvPath)
	require.Error(t, err)
}

// TestNewJournalReadsNestedCompletedFilesOnRead verifies that the current
// nested CompletedFiles JSON format is loaded into the in-memory nested set.
func TestNewJournalReadsNestedCompletedFilesOnRead(t *testing.T) {
	journalFile := filepath.Join(t.TempDir(), "journal.json")
	raw := map[string]any{
		"CompletedFiles": map[string]map[string]struct{}{
			"testdata": {
				"0-99999.gz":       {},
				"200000-299999.gz": {},
			},
		},
	}
	buf, err := json.Marshal(raw)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(journalFile, buf, 0o644))

	j, err := NewJournal(journalFile, testJobConfig(t), csvPath)
	require.NoError(t, err)

	require.Equal(t, normalizedCSVSet(0, 2), j.CompletedFiles)
}

// TestPendingFilesEquivalentIngestRootsShareProgress verifies that equivalent
// ingest roots with the same basename share completed-file state.
func TestPendingFilesEquivalentIngestRootsShareProgress(t *testing.T) {
	firstRoot := makeEquivalentIngestRoot(t, "external", "same-log", []string{"0-9.gz", "10-19.gz"})
	secondRoot := makeEquivalentIngestRoot(t, "data", "same-log", []string{"0-9.gz", "10-19.gz", "20-29.gz"})

	journalFile := filepath.Join(t.TempDir(), "journal.json")
	j, err := NewJournal(journalFile, testJobConfig(t), firstRoot)
	require.NoError(t, err)
	require.NoError(t, j.AddCompletedFiles([]string{
		filepath.Join(firstRoot, "bundled", "0-9.gz"),
		filepath.Join(firstRoot, "bundled", "10-19.gz"),
	}))

	j, err = NewJournal(journalFile, testJobConfig(t), secondRoot)
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
	j, err := NewJournal(journalFile, testJobConfig(t), firstRoot)
	require.NoError(t, err)
	require.NoError(t, j.AddCompletedFiles([]string{filepath.Join(firstRoot, "bundled", "0-9.gz")}))

	j, err = NewJournal(journalFile, testJobConfig(t), secondRoot)
	require.NoError(t, err)

	got, err := j.PendingFiles()
	require.NoError(t, err)
	require.Equal(t, []string{filepath.Join(secondRoot, "bundled", "0-9.gz")}, got)
}

// TestAddCompletedFilesDeduplicatesEquivalentRoots checks that adding the same
// normalized file through equivalent ingest roots remains idempotent.
func TestAddCompletedFilesDeduplicatesEquivalentRoots(t *testing.T) {
	firstRoot := makeEquivalentIngestRoot(t, "external", "same-log", []string{"0-9.gz"})
	secondRoot := makeEquivalentIngestRoot(t, "data", "same-log", []string{"0-9.gz"})

	journalFile := filepath.Join(t.TempDir(), "journal.json")
	j, err := NewJournal(journalFile, testJobConfig(t), firstRoot)
	require.NoError(t, err)

	require.NoError(t, j.AddCompletedFiles([]string{
		filepath.Join(firstRoot, "bundled", "0-9.gz"),
		filepath.Join(secondRoot, "bundled", "0-9.gz"),
	}))
	require.Equal(t, map[string]map[string]struct{}{"same-log": {"0-9.gz": {}}}, j.CompletedFiles)
}

// TestNewJournalRejectsMalformedCompletedFilesEncoding verifies that an
// unsupported CompletedFiles JSON encoding is rejected.
func TestNewJournalRejectsMalformedCompletedFilesEncoding(t *testing.T) {
	journalFile := filepath.Join(t.TempDir(), "journal.json")
	raw := map[string]any{
		"CompletedFiles": []string{"bad-entry-without-slash"},
	}
	buf, err := json.Marshal(raw)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(journalFile, buf, 0o644))

	_, err = NewJournal(journalFile, testJobConfig(t), csvPath)
	require.Error(t, err)
}

// TestWritePersistsNestedCompletedFilesJSON verifies that Write persists
// CompletedFiles using the nested JSON object format.
func TestWritePersistsNestedCompletedFilesJSON(t *testing.T) {
	journalFile := filepath.Join(t.TempDir(), "journal.json")
	j, err := NewJournal(journalFile, testJobConfig(t), csvPath)
	require.NoError(t, err)
	require.NoError(t, j.AddCompletedFiles([]string{csvFiles[0], csvFiles[2]}))

	buf, err := os.ReadFile(journalFile)
	require.NoError(t, err)

	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(buf, &raw))

	var completed map[string]map[string]struct{}
	require.NoError(t, json.Unmarshal(raw["CompletedFiles"], &completed))
	require.Equal(t, normalizedCSVSet(0, 2), completed)
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
	j, err := NewJournal(journalFile, testJobConfig(t), root)
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

func requireJSONDoesNotContainFiles(t *testing.T, journalFile string) {
	t.Helper()
	buf, err := os.ReadFile(journalFile)
	require.NoError(t, err)
	require.NotContains(t, string(buf), "\"Files\"")
}

// testJobConfig returns a JobConfiguration with "onlyingest" and batch size of 2.
func testJobConfig(t *testing.T) JobConfiguration {
	t.Helper()
	cfg, err := NewJobConfiguration("onlyingest", 2)
	require.NoError(t, err)
	return cfg
}

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
