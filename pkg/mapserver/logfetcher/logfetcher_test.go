package logfetcher

import (
	"context"
	"testing"
	"time"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/stretchr/testify/require"
)

// TODO(juagargi) allow mocking the fetching from the internet and run local

const ctURL = "https://ct.googleapis.com/logs/argon2021"

func TestGetCerts(t *testing.T) {
	stopChan := make(chan struct{})
	start := 1 * 1000 * 1000
	count := 100
	certs, err := getCerts(ctURL, start, start+count-1, stopChan)
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
			stopChan := make(chan struct{})
			certs, err := getCertificates(ctURL, tc.start, tc.end, tc.numWorkers, stopChan)
			require.NoError(t, err)
			require.Len(t, certs, tc.end-tc.start+1,
				"got %d instead of %d", len(certs), tc.end-tc.start+1)
		})
	}
}

func TestLogFetcher(t *testing.T) {
	cases := map[string]struct {
		start      int
		end        int
		numWorkers int
		batchSize  int
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
		"100_1_0": {
			start:      2000,
			end:        2100 - 1,
			numWorkers: 1,
		},
		"100_1_2": {
			start:      2000,
			end:        2100 - 1,
			numWorkers: 1,
			batchSize:  2,
		},
		"100_3_0": {
			start:      2000,
			end:        2100 - 1,
			numWorkers: 3,
		},
		"100_7_13": {
			start:      2000,
			end:        2100 - 1,
			numWorkers: 7,
			batchSize:  13,
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancelF()
			f := &LogFetcher{
				URL:         ctURL,
				Start:       tc.start,
				End:         tc.end,
				WorkerCount: tc.numWorkers,
				BatchSize:   tc.batchSize,
			}
			f.StartFetching()

			allCerts := make([]*ctx509.Certificate, 0)
			for {
				certs, err := f.NextBatch(ctx)
				require.NoError(t, err)
				require.LessOrEqual(t, len(certs), f.BatchSize,
					"got %d instead of %d", len(certs), tc.batchSize)
				allCerts = append(allCerts, certs...)
				if certs == nil && err == nil {
					break
				}
			}

			require.Len(t, allCerts, tc.end-tc.start+1,
				"got %d instead of %d", len(allCerts), tc.end-tc.start+1)
			certs, err := f.NextBatch(ctx)
			require.NoError(t, err)
			require.Nil(t, certs)
		})
	}
}

func TestTimeoutLogFetcher(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancelF()
	f := &LogFetcher{
		URL:         ctURL,
		Start:       2000,
		End:         2000 * 2000,
		BatchSize:   1,
		WorkerCount: 1,
	}
	certs, err := f.FetchAllCertificates(ctx)
	require.Error(t, err)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Len(t, certs, 0)
}
