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
	require.NoError(t, os.Remove(filename))

	require.Equal(t, prefix, filename[:len(prefix)])
	require.Equal(t, suffix, filename[len(filename)-len(suffix):])

	// Measure after first use.
	allocs := tests.AllocsPerRun(func() {
		filename, err = CreateTempFile(pathStorage, prefix, suffix)
	})
	t.Logf("created file %s", filename)
	require.NoError(t, err)
	require.Equal(t, 0, allocs)
	require.NoError(t, os.Remove(filename))
}
