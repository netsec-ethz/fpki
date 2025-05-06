package journal

import (
	"flag"
	"os"
	"testing"

	"github.com/netsec-ethz/fpki/cmd/ingest/cmdflags"
	"github.com/stretchr/testify/require"
)

func TestNewJournal(t *testing.T) {
	const (
		journalFile = "testdata/newjournal.json"
		csvPath     = "testdata/"
		csvFile1    = "testdata/bundled/file1.gz"
		csvFile2    = "testdata/bundled/file2.gz"
	)

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
	require.Equal(t, csvPath, flag.Arg(0))          //
	j, err = NewJournal(journalFile)                // Create new journal with a mock CSV path
	require.NoError(t, err)                         //
	require.Equal(t, 2, len(j.Files))               // We should have the two existing CSV files
	require.Equal(t, 0, len(j.CompletedFiles))      // But no completed jobs

	// Add a new CSV as processed.
	err = j.AddCompletedFiles([]string{csvFile1})
	require.NoError(t, err)
	// Open journal and check that we have one CSV processed already.
	j, err = NewJournal(journalFile)
	require.NoError(t, err)
	require.Equal(t, 2, len(j.Files))
	require.Equal(t, 1, len(j.CompletedFiles))
	require.Equal(t, csvFile1, j.CompletedFiles[0])
}
