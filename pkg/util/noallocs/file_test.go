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

	allocs := tests.AllocsPerRun(func() {
		fd, err = Open(storage, filename)
	})
	require.NoError(t, err)
	require.Equal(t, 0, allocs)

	linePattern := "hello world\n"

	// Write and check allocations.
	data := []byte(linePattern)
	allocs = tests.AllocsPerRun(func() {
		err = Write(fd, data)
	})
	require.NoError(t, err)
	require.Equal(t, 0, allocs)

	// Append and check allocations.
	allocs = tests.AllocsPerRun(func() {
		err = Write(fd, data)
	})
	require.NoError(t, err)
	require.Equal(t, 0, allocs)

	// Close.
	allocs = tests.AllocsPerRun(func() {
		err = Close(fd)
	})
	require.NoError(t, err)
	require.Equal(t, 0, allocs)

	// Check contents.
	contents, err := os.ReadFile(filename)
	require.NoError(t, err)
	expected := []byte(linePattern + linePattern)
	require.Equal(t, expected, contents)

	// Cleanup.
	_, err = os.Create(filename)
	require.NoError(t, err)
}
