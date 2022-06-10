package logpicker

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TODO(juagargi) allow mocking the fetching from the internet and run local

const ctURL = "https://ct.googleapis.com/logs/argon2021"

func TestGetCerts(t *testing.T) {
	start := 1 * 1000 * 1000
	count := 100
	certs, err := getCerts(ctURL, start, start+count-1)
	require.NoError(t, err)
	require.Len(t, certs, 100, "got %d", len(certs))
}

func TestDownloadCertSize(t *testing.T) {
	cases := map[string]struct {
		start      int
		end        int
		numWorkers int
	}{
		"0": {
			start:      2000,
			end:        2000 - 1,
			numWorkers: 1,
		},
		"1": {
			start:      2000,
			end:        2000,
			numWorkers: 1,
		},
		"2": {
			start:      2000,
			end:        2001,
			numWorkers: 1,
		},
		"100_1": {
			start:      2000,
			end:        2100 - 1,
			numWorkers: 1,
		},
		"100_3": {
			start:      2000,
			end:        2100 - 1,
			numWorkers: 3,
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			certs, err := GetCertificates(ctURL, tc.start, tc.end, tc.numWorkers)
			require.NoError(t, err)
			require.Len(t, certs, tc.end-tc.start+1,
				"got %d instead of %d", len(certs), tc.end-tc.start+1)
		})
	}
}
