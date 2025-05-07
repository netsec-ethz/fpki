package journal

import (
	"flag"
	"fmt"
	"os"
	"slices"
	"testing"

	"github.com/netsec-ethz/fpki/cmd/ingest/cmdflags"
	"github.com/stretchr/testify/require"
)

const csvPath = "testdata/"

var csvFiles = [...]string{
	"testdata/bundled/0-99999.gz",
	"testdata/bundled/100000-199999.gz",
	"testdata/bundled/200000-299999.gz",
}

func TestNewJournal(t *testing.T) {
	journalFile := fmt.Sprintf("testdata/journal-%s.json", t.Name())
	os.Remove(journalFile)       // ensure there is no file with this name
	defer os.Remove(journalFile) // remove it if we create it

	// Configure the CLI flags as the command does.
	cmdflags.ConfigureFlags()

	j, err := NewJournal(journalFile)
	require.NoError(t, err)
	require.Equal(t, journalFile, j.JournalFile)
	// Check we created the journal file.
	require.FileExists(t, journalFile)

	// Check journal.
	require.Empty(t, j.CompletedFiles)
	require.Empty(t, j.Files)

	// Open journal again.
	j, err = NewJournal(journalFile)
	require.NoError(t, err)
	// Check everything again.
	require.Equal(t, journalFile, j.JournalFile)
	require.FileExists(t, journalFile)
	require.Empty(t, j.CompletedFiles)
	require.Empty(t, j.Files)

	// Now create the journal again, but mock two CSV files to be processed.
	err = os.Remove(journalFile)                    // Remove journal
	require.NoError(t, err)                         //
	err = flag.CommandLine.Parse([]string{csvPath}) // mock CSV path
	require.NoError(t, err)                         //
	require.Equal(t, csvPath, flag.Arg(0))          // Assert that indeed the path is there
	j, err = NewJournal(journalFile)                // Create new journal with a mock CSV path
	require.NoError(t, err)                         //
	require.Equal(t, len(csvFiles), len(j.Files))   // We should have the two existing CSV files
	require.Equal(t, 0, len(j.CompletedFiles))      // But no completed jobs

	// Add a new CSV as processed.
	err = j.AddCompletedFiles(csvFiles[:1])
	require.NoError(t, err)
	// Open journal and check that we have one CSV processed already.
	j, err = NewJournal(journalFile)
	require.NoError(t, err)
	require.Equal(t, len(csvFiles), len(j.Files))
	require.Equal(t, 1, len(j.CompletedFiles))
	require.Equal(t, csvFiles[0], j.CompletedFiles[0])
}

func TestAddCompletedFiles(t *testing.T) {
	expected := slices.Clone(csvFiles[:])
	journalFile := fmt.Sprintf("testdata/journal-%s.json", t.Name())
	os.Remove(journalFile)       // ensure there is no file with this name
	defer os.Remove(journalFile) // remove it if we create it

	// Configure the CLI flags as the command does.
	cmdflags.ConfigureFlags()

	err := flag.CommandLine.Parse([]string{csvPath}) // mock CSV path
	require.NoError(t, err)                          //
	require.Equal(t, csvPath, flag.Arg(0))           // Assert that indeed the path is there

	j, err := NewJournal(journalFile)
	require.NoError(t, err)

	got := j.PendingFiles()
	require.Len(t, got, len(expected)) // none completed
	require.Equal(t, j.Files, got)

	// Add one completed file, the first one.
	err = j.AddCompletedFiles(expected[0:1])
	require.NoError(t, err)

	got = j.PendingFiles()
	expected = slices.Delete(expected, 0, 1)
	// expected is now [ 100000- ,200000- ]
	require.Len(t, got, len(expected)) // one  completed
	require.Equal(t, expected, got)

	// Complete another one, this time the last file.
	err = j.AddCompletedFiles(expected[len(expected)-1:])
	require.NoError(t, err)

	got = j.PendingFiles()
	expected = slices.Delete(expected, len(expected)-1, len(expected))
	// expected is now [ 100000- ]
	require.Len(t, got, len(expected)) // two  completed
	require.Equal(t, expected, got)

	require.Equal(t, csvFiles[1], got[0])
	require.Len(t, got, 1)
}

func TestPendingFiles(t *testing.T) {

}
