package journal

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
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
	require.Empty(t, j.Files)

	// Recreate.
	j, err = NewJournal(journalFile, testJobConfig(t), "")
	require.NoError(t, err)
	require.Equal(t, journalFile, j.JournalFile)
	require.FileExists(t, journalFile)
	require.Empty(t, j.CompletedFiles)
	require.Empty(t, j.Files)

	// Recreate, with existing non-processed files.
	journalFile = filepath.Join(t.TempDir(), "with-files.json")
	j, err = NewJournal(journalFile, testJobConfig(t), csvPath)
	require.NoError(t, err)
	require.Len(t, j.Files, len(csvFiles))
	require.Empty(t, j.CompletedFiles)

	// Add one file as completed.
	err = j.AddCompletedFiles(csvFiles[:1])
	require.NoError(t, err)
	// Check that the completed file is there.
	j, err = NewJournal(journalFile, testJobConfig(t), csvPath)
	require.NoError(t, err)
	require.Len(t, j.Files, len(csvFiles))
	require.Len(t, j.CompletedFiles, 1)
	require.Equal(t, csvFiles[0], j.CompletedFiles[0])
}

// TestAddCompletedFiles checks that AddCompletedFiles correctly adds the file names,
// and that the list is kept sorted and without duplicates.
func TestAddCompletedFiles(t *testing.T) {
	expected := slices.Clone(csvFiles[:])
	journalFile := filepath.Join(t.TempDir(), fmt.Sprintf("%s.json", t.Name()))

	j, err := NewJournal(journalFile, testJobConfig(t), csvPath)
	require.NoError(t, err)

	got := j.PendingFiles()
	require.Len(t, got, len(expected))
	require.Equal(t, j.Files, got)

	// Add the first file 0-99999.
	err = j.AddCompletedFiles(expected[0:1])
	require.NoError(t, err)
	got = j.PendingFiles()
	expected = slices.Delete(expected, 0, 1)
	require.Equal(t, expected, got)

	// Add the last file 200000-299999.
	err = j.AddCompletedFiles(expected[len(expected)-1:])
	require.NoError(t, err)
	got = j.PendingFiles()
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

	require.Equal(t, []string{csvFiles[1]}, j.PendingFiles())
}

func TestNewJournalInvalidJSON(t *testing.T) {
	journalFile := filepath.Join(t.TempDir(), "invalid.json")
	err := os.WriteFile(journalFile, []byte("{"), 0o644)
	require.NoError(t, err)

	_, err = NewJournal(journalFile, testJobConfig(t), csvPath)
	require.Error(t, err)
}

// TestNewJournalNormalizesFilesOnRead checks that reading a json journal actually normalizes
// the content of Files and CompletedFiles to sorted and not duplicated.
func TestNewJournalNormalizesFilesOnRead(t *testing.T) {
	journalFile := filepath.Join(t.TempDir(), "journal.json")
	raw := Journal{
		Files: []string{
			csvFiles[2],
			csvFiles[0],
			csvFiles[1],
			csvFiles[0],
		},
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

	require.Equal(t, []string{csvFiles[0], csvFiles[1], csvFiles[2]}, j.Files)
	require.Equal(t, []string{csvFiles[0], csvFiles[2]}, j.CompletedFiles)
	require.Equal(t, []string{csvFiles[1]}, j.PendingFiles())
}

func TestNewJournalFailsWhenReadNeedsInvalidFilenameNormalization(t *testing.T) {
	journalFile := filepath.Join(t.TempDir(), "journal.json")
	raw := Journal{
		Files: []string{
			"invalid-file-name",
			csvFiles[0],
		},
	}
	buf, err := json.Marshal(raw)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(journalFile, buf, 0o644))

	_, err = NewJournal(journalFile, testJobConfig(t), csvPath)
	require.Error(t, err)
}

// testJobConfig returns a JobConfiguration with "onlyingest" and batch size of 2.
func testJobConfig(t *testing.T) JobConfiguration {
	t.Helper()
	cfg, err := NewJobConfiguration("onlyingest", 2)
	require.NoError(t, err)
	return cfg
}
