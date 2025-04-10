package noallocs

import (
	"os"
	"testing"

	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/stretchr/testify/require"
)

func TestWrite(t *testing.T) {
	filename := "testdata/empty.dat"
	os.Remove(filename)
	storage := make([]byte, len(filename)+1)
	copy(storage, filename)

	// Warm up.
	fd, err := Open(storage, filename)
	require.NoError(t, err)
	require.GreaterOrEqual(t, fd, 0)

	linePattern := "hello world\n"

	// Write.
	data := []byte(linePattern)
	err = Write(fd, data)
	require.NoError(t, err)

	// Append.
	err = Write(fd, data)
	require.NoError(t, err)

	// Close.
	err = Close(fd)
	require.NoError(t, err)

	// Check contents.
	contents, err := os.ReadFile(filename)
	require.NoError(t, err)
	expected := []byte(linePattern + linePattern)
	require.Equal(t, expected, contents)

	// Cleanup.
	_, err = os.Create(filename)
	require.NoError(t, err)
}

func TestWriteAllocations(t *testing.T) {
	filename := "testdata/empty2.dat"
	os.Remove(filename)
	storage := make([]byte, len(filename)+1)
	copy(storage, filename)

	// Warm up.
	fd, err := Open(storage, filename)
	require.NoError(t, err)
	require.GreaterOrEqual(t, fd, 0)

	allocs := tests.AllocsPerRun(func(tests.B) {
		fd, err = Open(storage, filename)
	})
	require.NoError(t, err)
	require.Equal(t, 0, allocs)

	linePattern := "hello world\n"
	data := []byte(linePattern)
	allocs = tests.AverageAllocsPerRun(func(tests.B) {
		err = Write(fd, data)
	})
	require.NoError(t, err)
	require.Equal(t, 0, allocs)

	// Append and check allocations.
	allocs = tests.AverageAllocsPerRun(func(tests.B) {
		err = Write(fd, data)
	})
	require.NoError(t, err)
	require.Equal(t, 0, allocs)

	// Close.
	allocs = tests.AllocsPerRun(func(tests.B) {
		err = Close(fd)
	})
	require.NoError(t, err)
	require.Equal(t, 0, allocs)

	// Cleanup, return to empty.
	_, err = os.Create(filename)
	require.NoError(t, err)
}
