package util

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEstimateNumCertsFromGzCsvFilename(t *testing.T) {
	testCases := []struct {
		filename string
		count    uint
	}{
		{
			filename: "0-100005.gz",
			count:    100006,
		},
		{
			filename: "400024-500029.csv",
			count:    100006,
		},
		{
			filename: "/tmp/6500632-6600651.gz",
			count:    100020,
		},
		{
			filename: "9901114-10001130.gz",
			count:    100017,
		},
		{
			filename: "/mnt/data/certstore/26503585-26603587.gz",
			count:    100003,
		},
		{
			filename: "47906379-48006394.gz",
			count:    100016,
		},
	}

	for _, tc := range testCases {
		got, err := EstimateCertCount(tc.filename)
		require.NoError(t, err)
		require.Equal(t, tc.count, got)
	}
}
