package mapserver_test

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/netsec-ethz/fpki/pkg/mapserver"
	"github.com/netsec-ethz/fpki/pkg/mapserver/config"
	"github.com/netsec-ethz/fpki/pkg/tests/testdb"
	tup "github.com/netsec-ethz/fpki/pkg/tests/updater"
	"github.com/netsec-ethz/fpki/pkg/util"
	"github.com/stretchr/testify/require"
)

func TestServer(t *testing.T) {
	// Because we are using "random" bytes deterministically here, set a fixed seed.
	rand.Seed(1)

	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	// Configure a test DB.
	dbConf, removeF := testdb.ConfigureTestDB(t)
	defer removeF()

	// Connect to the DB.
	conn := testdb.Connect(t, dbConf)
	defer conn.Close()

	// Insert mock data.
	numDifferentDomains := 10
	domains := make([]string, numDifferentDomains)
	certsOnly := make([]tup.CertsPoliciesOrBoth, numDifferentDomains)
	for i := range domains {
		domains[i] = fmt.Sprintf("domain%d", i)
		certsOnly[i] = tup.CertsOnly
	}
	tup.UpdateDBwithRandomCerts(ctx, t, conn, domains, certsOnly)
	t.Log("Mock data in DB")

	// Create a MapServer
	conf := &config.Config{
		UpdateTimer:        util.DurationWrap{Duration: 24 * time.Hour},
		UpdateAt:           util.NewTimeOfDay(3, 0, 0, 0),
		CTLogServerURLs:    []string{"https://invalid.netsec.ethz.ch"},
		DBConfig:           dbConf,
		CertificatePemFile: "../../tests/testdata/servercert.pem",
		PrivateKeyPemFile:  "../../tests/testdata/serverkey.pem",
	}

	// Run mapserver:
	server, err := mapserver.NewMapServer(ctx, conf)
	require.NoError(t, err)
	// Start serving requests.
	wg := sync.WaitGroup{}
	wg.Add(1) // Done at each iteration
	wgShutdown := sync.WaitGroup{}
	wgShutdown.Add(1) // Done when no more Listen.
	listeningCount := 0
	go func() {
		defer wgShutdown.Done()

		// We will shutdown the server and expect it to be up once more.
		for listeningCount < 2 {
			err = server.Listen(ctx)
			require.NoError(t, err, "iteration %d", listeningCount)
			listeningCount++
			wg.Done()
		}
	}()

	time.Sleep(time.Millisecond)
	N := 1000
	// Prepare the client.
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{
		Transport: tr,
	}

	wgClients := sync.WaitGroup{}
	wgClients.Add(N)
	t.Log("Starting clients")
	for i := 0; i < N; i++ {
		go func() {
			defer wgClients.Done()

			resp, err := client.Get(fmt.Sprintf("https://localhost:%d/getproof?domain=%s",
				mapserver.APIPort, domains[rand.Intn(len(domains))]))
			require.NoError(t, err)
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
		}()
	}
	wgClients.Wait()
	server.Shutdown(ctx)
	wg.Wait()
	require.Equal(t, 1, listeningCount)
	wg.Add(1) // Restart the wg prior to check the next iteration in this goroutine.

	time.Sleep(time.Millisecond)
	server.Shutdown(ctx)
	wg.Wait()
	require.Equal(t, 2, listeningCount)
	wgShutdown.Wait()
}

// BenchmarkAPIGetProof1K uses 671839 ns/op .
func BenchmarkAPIGetProof1K(b *testing.B) {
	benchmarkAPIGetProof(b, 1000)
}

func benchmarkAPIGetProof(b *testing.B, numDifferentDomains int) {
	// Because we are using "random" bytes deterministically here, set a fixed seed.
	rand.Seed(1)

	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	// Configure a test DB.
	dbConf, removeF := testdb.ConfigureTestDB(b)
	defer removeF()

	// Connect to the DB.
	conn := testdb.Connect(b, dbConf)
	defer conn.Close()

	// Insert mock data.
	domains := make([]string, numDifferentDomains)
	certsOnly := make([]tup.CertsPoliciesOrBoth, numDifferentDomains)
	for i := range domains {
		domains[i] = fmt.Sprintf("domain%d", i)
		certsOnly[i] = tup.CertsOnly
	}
	tup.UpdateDBwithRandomCerts(ctx, b, conn, domains, certsOnly)

	// Create a MapServer
	conf := &config.Config{
		UpdateTimer:        util.DurationWrap{Duration: 24 * time.Hour},
		UpdateAt:           util.NewTimeOfDay(3, 0, 0, 0),
		CTLogServerURLs:    []string{"https://invalid.netsec.ethz.ch"},
		DBConfig:           dbConf,
		CertificatePemFile: "../../tests/testdata/servercert.pem",
		PrivateKeyPemFile:  "../../tests/testdata/serverkey.pem",
	}

	// Run mapserver:
	server, err := mapserver.NewMapServer(ctx, conf)
	require.NoError(b, err)
	// Start serving requests.
	go func() {
		err = server.Listen(ctx)
		require.NoError(b, err)
	}()
	time.Sleep(time.Millisecond)
	defer server.Shutdown(ctx)

	// Prepare the client.
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{
		Transport: tr,
	}

	// Benchmark with concurrent clients.
	wg := sync.WaitGroup{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			resp, err := client.Get(fmt.Sprintf("https://localhost:%d/getproof?domain=%s",
				mapserver.APIPort, domains[rand.Intn(len(domains))]))
			b.StopTimer()
			require.NoError(b, err)
			body, err := io.ReadAll(resp.Body)
			require.NoError(b, err)
			require.Equal(b, http.StatusOK, resp.StatusCode, string(body))
			b.StartTimer()
		}()
	}
	wg.Wait()
}

// BenchmarkAPIGetPayloads1K uses 827523 ns/op .
func BenchmarkAPIGetPayloads1K(b *testing.B) {
	benchmarkAPIGetPayloads(b, 1000)
}

func benchmarkAPIGetPayloads(b *testing.B, numDifferentDomains int) {
	// Because we are using "random" bytes deterministically here, set a fixed seed.
	rand.Seed(1)

	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	// Configure a test DB.
	dbConf, removeF := testdb.ConfigureTestDB(b)
	defer removeF()

	// Connect to the DB.
	conn := testdb.Connect(b, dbConf)
	defer conn.Close()

	domains := make([]string, numDifferentDomains)
	certsOnly := make([]tup.CertsPoliciesOrBoth, numDifferentDomains)
	for i := range domains {
		domains[i] = fmt.Sprintf("domain%d", i)
		certsOnly[i] = tup.CertsOnly
	}
	_, _, certIDs, _, _ := tup.UpdateDBwithRandomCerts(ctx, b, conn, domains, certsOnly)

	// Create a MapServer
	conf := &config.Config{
		UpdateTimer:        util.DurationWrap{Duration: 24 * time.Hour},
		UpdateAt:           util.NewTimeOfDay(3, 0, 0, 0),
		CTLogServerURLs:    []string{"https://invalid.netsec.ethz.ch"},
		DBConfig:           dbConf,
		CertificatePemFile: "../../tests/testdata/servercert.pem",
		PrivateKeyPemFile:  "../../tests/testdata/serverkey.pem",
	}

	// Run mapserver:
	server, err := mapserver.NewMapServer(ctx, conf)
	require.NoError(b, err)
	// Start serving requests.
	go func() {
		err = server.Listen(ctx)
		require.NoError(b, err)
	}()
	time.Sleep(time.Millisecond)
	defer server.Shutdown(ctx)

	// Prepare the client.
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{
		Transport: tr,
	}

	// Benchmark with concurrent clients.
	wg := sync.WaitGroup{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			ID := hex.EncodeToString(certIDs[rand.Intn(len(certIDs))][:])
			resp, err := client.Get(fmt.Sprintf("https://localhost:%d/getpayloads?ids=%s",
				mapserver.APIPort, ID))
			b.StopTimer()
			require.NoError(b, err)
			body, err := io.ReadAll(resp.Body)
			require.NoError(b, err)
			require.Equal(b, http.StatusOK, resp.StatusCode, string(body))
			b.StartTimer()
		}()
	}

	wg.Wait()
}
