package logfetcher

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/netsec-ethz/fpki/pkg/util"
)

// TODO(juagargi) allow mocking the fetching from the internet and run local

const testURL = "https://ct.googleapis.com/logs/argon2021"

func TestGetRawEntries(t *testing.T) {
	cases := map[string]struct {
		start int64
		end   int64
	}{
		"simple": {
			start: 0,
			end:   0,
		},
		"long": {
			start: 0,
			end:   511,
		},
		"non_aligned": {
			start: 0,
			end:   1,
		},
		"middle": {
			start: 2000,
			end:   2001,
		},
		"longer": {
			start: 2000,
			end:   2201,
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f, err := NewHttpLogFetcher(testURL)
			require.NoError(t, err)
			rawEntries := make([]*ct.LeafEntry, tc.end-tc.start+1)
			n, err := f.getRawEntries(rawEntries, tc.start, tc.end)
			require.NoError(t, err)
			require.Equal(t, tc.end-tc.start+1, n)
		})
	}
}

func TestStoppingGetRawEntries(t *testing.T) {
	f, err := NewHttpLogFetcher(testURL)
	require.NoError(t, err)
	f.start = 3000
	f.end = f.start + 10000

	// In 1 second, trigger a stop signal.
	go func() {
		time.Sleep(time.Second)
		f.StopFetching()
	}()
	// Manually call getRawEntries as if called from the parent.
	leafEntries := make([]*ct.LeafEntry, f.end-f.start+1)
	n, err := f.getRawEntries(leafEntries, f.start, f.end)
	require.NoError(t, err)
	require.Equal(t, int64(0), n)
}

func TestGetRawEntriesInBatches(t *testing.T) {
	cases := map[string]struct {
		start     int64
		end       int64
		batchSize int64
	}{

		"1": {
			start: 2000,
			end:   2000,
		},
		"2": {
			start: 2000,
			end:   2001,
		},
		"2_2": {
			start:     2000,
			end:       2001,
			batchSize: 2,
		},
		"3_2": {
			start:     2000,
			end:       2002,
			batchSize: 2,
		},
		"100": {
			start: 2000,
			end:   2100 - 1,
		},
		"100_2": {
			start:     2000,
			end:       2100 - 1,
			batchSize: 2,
		},
		"100_13": {
			start:     2000,
			end:       2100 - 1,
			batchSize: 13,
		},
		"long": {
			start:     0,
			end:       128,
			batchSize: 1,
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f, err := NewHttpLogFetcher(testURL)
			require.NoError(t, err)
			if tc.batchSize != 0 {
				f.serverBatchSize = tc.batchSize
				f.processBatchSize = f.serverBatchSize * 128
			}

			entries := make([]*ct.LeafEntry, tc.end-tc.start+1)
			n, err := f.getRawEntriesInBatches(entries, tc.start, tc.end)
			require.NoError(t, err)
			expected := tc.end - tc.start + 1
			require.Equal(t, expected, n)
		})
	}
}

func TestStoppingGetRawEntriesInBatches(t *testing.T) {
	// Prepare a test case for getRawEntriesInBatches, where the server responds in batches of 1
	// element, and we process in batches of 100K.
	// This means that getRawEntriesInBatches will have to make 100K calls to getRawEntries,
	// and in the middle of them, we will request to stop the fetcher.
	f, err := NewHttpLogFetcher(testURL)
	require.NoError(t, err)
	f.serverBatchSize = 1
	f.processBatchSize = 100000
	f.start = 3000
	f.end = f.start + 3000*3000 // Whatever but larger than processBatchSize

	// Trigger a stop signal after 1 sec. Fast enough for getRawEntriesInBatches to not be done yet
	go func() {
		time.Sleep(1 * time.Second)
		f.StopFetching()
	}()

	// Manually call getRawEntriesInBatches as if called from "fetch()".
	leafEntries := make([]*ct.LeafEntry, f.processBatchSize)
	start := f.start
	end := f.start + f.processBatchSize - 1
	n, err := f.getRawEntriesInBatches(leafEntries, start, end)
	require.NoError(t, err)
	// Some leaves where downloaded.
	require.Greater(t, n, int64(0))
	// But not all.
	require.Less(t, n, f.processBatchSize)

	// Check that all leaves returned are non nil.
	for i := range leafEntries[:n] {
		require.NotNil(t, leafEntries[i], "nil leaf at %d", i)
	}
}

func TestLogFetcher(t *testing.T) {
	cases := map[string]struct {
		start     int
		end       int
		batchSize int
	}{
		"0": {
			start: 2000,
			end:   2000 - 1,
		},
		"1": {
			start: 2000,
			end:   2000,
		},
		"2": {
			start: 2000,
			end:   2001,
		},
		"6_1": {
			start:     2000,
			end:       2005,
			batchSize: 1,
		},
		"100": {
			start: 2000,
			end:   2100 - 1,
		},
		"100_2": {
			start:     2000,
			end:       2100 - 1,
			batchSize: 2,
		},
		"100_13": {
			start:     2000,
			end:       2100 - 1,
			batchSize: 13,
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancelF()
			f, err := NewHttpLogFetcher(testURL)
			require.NoError(t, err)
			if tc.batchSize > 0 {
				f.serverBatchSize = int64(tc.batchSize)
				f.processBatchSize = 128 * f.serverBatchSize
			}
			f.StartFetching(int64(tc.start), int64(tc.end))

			allCerts := make([]*ctx509.Certificate, 0)
			allChains := make([][]*ctx509.Certificate, 0)
			for f.NextBatch(ctx) {
				certs, chains, _, err := f.ReturnNextBatch()
				require.NoError(t, err)
				require.LessOrEqual(t, len(certs), int(f.processBatchSize),
					"%d is not <= than %d", len(certs), f.processBatchSize)
				allCerts = append(allCerts, certs...)
				allChains = append(allChains, chains...)
				if certs == nil && err == nil {
					break
				}
			}
			require.Len(t, allCerts, tc.end-tc.start+1,
				"got %d instead of %d", len(allCerts), tc.end-tc.start+1)
			require.Len(t, allChains, tc.end-tc.start+1,
				"got %d instead of %d", len(allChains), tc.end-tc.start+1)

			// Again. It should return empty.
			ok := f.NextBatch(ctx)
			require.False(t, ok)
			f.StopFetching()
		})
	}
}

func TestTimeoutLogFetcher(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelF()
	f, err := NewHttpLogFetcher(testURL)
	require.NoError(t, err)

	// Attempt to fetch something really big that would need more than 1 sec.
	certs, chains, _, err := f.FetchAllCertificates(ctx, 2000, 666000000)
	require.Error(t, err)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Len(t, certs, 0)
	require.Len(t, chains, 0)
}

func TestSpeed(t *testing.T) {
	tests.SkipExpensiveTest(t)

	ctx, cancelF := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancelF()
	f, err := NewHttpLogFetcher(testURL)
	require.NoError(t, err)
	t0 := time.Now()
	start := int64(18000)
	end := start + 10000 - 1
	_, _, _, err = f.FetchAllCertificates(ctx, start, end)
	t1 := time.Now()
	elapsed := t1.Sub(t0)
	fmt.Printf("Elapsed: %s, %f certs / minute\n",
		elapsed, float64(end-start+1)/elapsed.Minutes())
	require.NoError(t, err)
}

// TestGetSize checks that the client's function to retrieve the current size works.
func TestGetSize(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelF()

	// Configure client.
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConnsPerHost:   10,
			DisableKeepAlives:     false,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	opts := jsonclient.Options{UserAgent: "ct-go-ctclient/1.0"}
	ctClient, err := client.New(testURL, httpClient, opts)
	require.NoError(t, err)
	// Call GetSTH to obtain the size.
	sth, err := ctClient.GetSTH(ctx)
	require.NoError(t, err)
	t.Logf("tree size is %d", sth.TreeSize)
	tt := time.Unix(0, int64(sth.Timestamp))
	t.Logf("timestamp raw: %d parsed: %s", sth.Timestamp, tt)
	t.Logf("timestamp raw: %d parsed: %s", sth.Timestamp, util.TimeFromSecs(int(sth.Timestamp/1000)))

	// Check that the size returned by the GetSize method is the same.
	f, err := NewHttpLogFetcher(testURL)
	require.NoError(t, err)
	s, err := f.GetCurrentState(ctx, State{})
	require.NoError(t, err)
	require.Equal(t, sth.TreeSize, s.Size)

	// Test that this is the correct size, because we cannot get negative entries or past this.
	_, err = ctClient.GetRawEntries(ctx, -1, 1)
	require.Error(t, err)
	// Zero is the first entry.
	res, err := ctClient.GetRawEntries(ctx, 0, 0)
	require.NoError(t, err)
	require.Equal(t, 1, len(res.Entries))
	// We can query the last item (which is size -1, as the first index is 0).
	res, err = ctClient.GetRawEntries(ctx, int64(s.Size)-1, int64(s.Size)-1)
	require.NoError(t, err)
	require.Equal(t, 1, len(res.Entries))
	// But we can't query past it.
	_, err = ctClient.GetRawEntries(ctx, int64(s.Size), int64(s.Size))
	require.Error(t, err)
}
