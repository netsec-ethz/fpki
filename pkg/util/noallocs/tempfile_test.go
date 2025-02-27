package noallocs

import (
	"os"
	"testing"

	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/stretchr/testify/require"
)

func TestCreateTempAllocs(t *testing.T) {
	prefix := "/tmp/blah-"
	suffix := ".csv"
	pathStorage := make([]byte, 2048) // all zeros

	// Warm up.
	filename, err := CreateTempFile(pathStorage, prefix, suffix)
	require.NoError(t, err)
	t.Logf("filename: %s", filename)
	require.NoError(t, os.Remove(filename))

	require.Equal(t, prefix, filename[:len(prefix)])
	require.Equal(t, suffix, filename[len(filename)-len(suffix):])
	t.Logf("random part: %s", filename[len(prefix):len(filename)-len(suffix)])

	// Measure after first use.
	allocs := tests.AllocsPerRun(func() {
		filename, err = CreateTempFile(pathStorage, prefix, suffix)
	})
	t.Logf("created file %s", filename)
	require.NoError(t, err)
	require.Equal(t, 0, allocs)
	require.NoError(t, os.Remove(filename))
}

func TestCreateTempSameFilename(t *testing.T) {
	prefix := "/tmp/foo-"
	suffix := ".csv"
	storage := make([]byte, 2048)
	prevFilename, err := CreateTempFile(storage, prefix, suffix)
	require.NoError(t, err)
	t.Logf("previous filename: %s", prevFilename)
	require.NoError(t, os.Remove(prevFilename))

	// Generate a new temporary file. It must modify the previous one.
	prevCopy := string(append([]byte(""), prevFilename...)) // Deep copy of previous filename.
	filename, err := CreateTempFile(storage, prefix, suffix)
	require.NoError(t, err)
	require.NoError(t, os.Remove(filename))
	t.Logf("prev copy: %s", prevCopy)
	t.Logf("new filename: %s", filename)
	// Check previously returned filename and current are the same.
	require.Equal(t, filename, prevFilename)
	// Check that the previous original filename is different.
	require.NotEqual(t, filename, prevCopy)
}
