package journal

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
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

var normalizedCSVFiles = [...]string{
	"testdata/0-99999.gz",
	"testdata/100000-199999.gz",
	"testdata/200000-299999.gz",
}

// TestSanityOfThisTest verifies that the content of the testdata/bundled directory is as expected.
func TestSanityOfThisTest(t *testing.T) {
	gotGz, gotCSV, err := ListCsvFiles(csvPath)
	require.NoError(t, err)

	require.Equal(t, csvFiles[:], gotGz)
	require.Empty(t, gotCSV)

	for _, filename := range csvFiles {
		require.FileExists(t, filename)
	}
}

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
	require.Len(t, j.CompletedFiles, 1)
	require.Equal(t, normalizedCSVFiles[0], j.CompletedFiles[0])
	requireJSONDoesNotContainFiles(t, journalFile)
}

// TestAddCompletedFiles checks that AddCompletedFiles correctly adds the file names,
// and that the list is kept sorted and without duplicates.
func TestAddCompletedFiles(t *testing.T) {
	expected := slices.Clone(csvFiles[:])
	journalFile := filepath.Join(t.TempDir(), fmt.Sprintf("%s.json", t.Name()))

	j, err := NewJournal(journalFile, testJobConfig(t), csvPath)
	require.NoError(t, err)

	got, err := j.PendingFiles()
	require.NoError(t, err)
	require.Len(t, got, len(expected))
	require.Equal(t, expected, got)

	// Add the first file 0-99999.
	err = j.AddCompletedFiles(expected[0:1])
	require.NoError(t, err)
	require.Equal(t, []string{normalizedCSVFiles[0]}, j.CompletedFiles)
	got, err = j.PendingFiles()
	require.NoError(t, err)
	expected = slices.Delete(expected, 0, 1)
	require.Equal(t, expected, got)

	// Add the last file 200000-299999.
	err = j.AddCompletedFiles(expected[len(expected)-1:])
	require.NoError(t, err)
	got, err = j.PendingFiles()
	require.NoError(t, err)
	expected = slices.Delete(expected, len(expected)-1, len(expected)) // remove last.
	require.Equal(t, expected, got)
	require.Len(t, got, 1)
	// Check that indeed the pending file is the second from csvFiles 100000-199999.
	require.Equal(t, csvFiles[1], got[0])
}

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

func TestNewJournalInvalidJSON(t *testing.T) {
	journalFile := filepath.Join(t.TempDir(), "invalid.json")
	err := os.WriteFile(journalFile, []byte("{"), 0o644)
	require.NoError(t, err)

	_, err = NewJournal(journalFile, testJobConfig(t), csvPath)
	require.Error(t, err)
}

// TestNewJournalNormalizesCompletedFilesOnRead checks that reading a json journal actually
// normalizes the content of CompletedFiles to sorted and not duplicated.
func TestNewJournalNormalizesCompletedFilesOnRead(t *testing.T) {
	journalFile := filepath.Join(t.TempDir(), "journal.json")
	raw := Journal{
		CompletedFiles: []string{
			csvFiles[2],
			csvFiles[0],
			csvFiles[2],
		},
	}
	buf, err := json.Marshal(raw)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(journalFile, buf, 0o644))

	j, err := NewJournal(journalFile, testJobConfig(t), csvPath)
	require.NoError(t, err)

	require.Equal(t, []string{normalizedCSVFiles[0], normalizedCSVFiles[2]}, j.CompletedFiles)
	got, err := j.PendingFiles()
	require.NoError(t, err)
	require.Equal(t, []string{csvFiles[1]}, got)
}

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

func TestNewJournalMigratesLegacyCompletedFilesAcrossEquivalentRoots(t *testing.T) {
	firstRoot := makeEquivalentIngestRoot(t, "external", "same-log", []string{"0-9.gz"})
	secondRoot := makeEquivalentIngestRoot(t, "data", "same-log", []string{"0-9.gz"})

	journalFile := filepath.Join(t.TempDir(), "journal.json")
	raw := Journal{
		CompletedFiles: []string{filepath.Join(firstRoot, "bundled", "0-9.gz")},
	}
	buf, err := json.Marshal(raw)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(journalFile, buf, 0o644))

	j, err := NewJournal(journalFile, testJobConfig(t), secondRoot)
	require.NoError(t, err)
	require.Equal(t, []string{filepath.Join("same-log", "0-9.gz")}, j.CompletedFiles)

	got, err := j.PendingFiles()
	require.NoError(t, err)
	require.Empty(t, got)
}

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
	require.Equal(t, []string{filepath.Join("same-log", "0-9.gz")}, j.CompletedFiles)
}

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

func TestPendingFilesLogsDirectoryListing(t *testing.T) {
	journalFile := filepath.Join(t.TempDir(), "journal.json")
	j, err := NewJournal(journalFile, testJobConfig(t), csvPath)
	require.NoError(t, err)

	output := captureStdout(t, func() {
		_, err := j.PendingFiles()
		require.NoError(t, err)
	})

	require.Contains(t, output, "Start listing directory...")
	require.Contains(t, output, "Finished listing directory in ")
	require.Len(t, strings.Split(strings.TrimSpace(output), "\n"), 3)
}

func requireJSONDoesNotContainFiles(t *testing.T, journalFile string) {
	t.Helper()
	buf, err := os.ReadFile(journalFile)
	require.NoError(t, err)
	require.NotContains(t, string(buf), "\"Files\"")
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	done := make(chan string, 1)
	go func() {
		buf, err := io.ReadAll(r)
		if err != nil {
			done <- ""
			return
		}
		done <- string(buf)
	}()

	fn()

	require.NoError(t, w.Close())
	os.Stdout = oldStdout
	output := <-done
	require.NoError(t, r.Close())
	return output
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
