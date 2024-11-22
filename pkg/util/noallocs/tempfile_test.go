package noallocs

import (
	"os"
	"testing"

	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/stretchr/testify/require"
)

func TestCreateTempAllocs(t *testing.T) {
	prefix := "/tmp/blah-"
	pathStorage := make([]byte, 2048) // all zeros

	// Warm up.
	filename, err := CreateTempFile(pathStorage, prefix)
	require.NoError(t, err)
	require.NoError(t, os.Remove(filename))

	// Measure after first use.
	allocs := tests.AllocsPerRun(func() {
		filename, err = CreateTempFile(pathStorage, prefix)
	})
	t.Logf("created file %s", filename)
	require.NoError(t, err)
	require.Equal(t, 0, allocs)
	require.NoError(t, os.Remove(filename))
}
