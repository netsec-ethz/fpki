package mapserver_test

import (
	"context"
	"crypto/tls"
	"fmt"
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

// BenchmarkAPIGetProof1K uses 5465454 ns/op .
func BenchmarkAPIGetProof1K(b *testing.B) {
	benchmarkAPIGetProof(b, 1000)
}

func benchmarkAPIGetProof(b *testing.B, numRequests int) {
	// Because we are using "random" bytes deterministically here, set a fixed seed.
	rand.Seed(1)

	// ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	ctx, cancelF := context.WithTimeout(context.Background(), time.Hour) //deleteme
	defer cancelF()

	// Configure a test DB.
	dbConf, removeF := testdb.ConfigureTestDB(b)
	defer removeF()

	// Connect to the DB.
	conn := testdb.Connect(b, dbConf)
	defer conn.Close()

	// certs, policies, _, _, _ :=
	tup.UpdateDBwithRandomCerts(ctx, b, conn, []string{
		"a.com",
		"b.com",
		"c.com"},
		[]tup.CertsPoliciesOrBoth{
			tup.CertsOnly,
			tup.PoliciesOnly,
			tup.BothCertsAndPolicies,
		})

	// Create a MapServer
	conf := &config.Config{
		UpdateTimer:        util.DurationWrap{Duration: 24 * time.Hour},
		UpdateAt:           util.NewTimeOfDay(3, 0, 0, 0),
		CTLogServerURLs:    []string{"https://invalid.netsec.ethz.ch"},
		DBConfig:           dbConf,
		CertificatePemFile: "../../tests/testdata/servercert.pem",
		PrivateKeyPemFile:  "../../tests/testdata/serverkey.pem",
	}
	// Mapserver:
	server, err := mapserver.NewMapServer(ctx, conf)
	require.NoError(b, err)
	// Start serving requests.
	go func() {
		err = server.Listen(ctx)
		require.NoError(b, err)
	}()
	time.Sleep(time.Millisecond)

	// Prepare the clients.
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

			resp, err := client.Get(fmt.Sprintf("https://localhost:%d/getproof?domain=a.com",
				mapserver.APIPort))
			b.StopTimer()
			require.NoError(b, err)
			require.Equal(b, http.StatusOK, resp.StatusCode)
			b.StartTimer()
		}()

		wg.Wait()
	}
}
