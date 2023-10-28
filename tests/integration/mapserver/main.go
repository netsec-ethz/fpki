package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/netsec-ethz/fpki/pkg/mapserver"
	"github.com/netsec-ethz/fpki/pkg/mapserver/config"
	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/netsec-ethz/fpki/pkg/tests/testdb"
	tup "github.com/netsec-ethz/fpki/pkg/tests/updater"
	"github.com/netsec-ethz/fpki/pkg/util"
	"github.com/stretchr/testify/require"
)

func main() {
	os.Exit(mainFunc())
}

func mainFunc() int {
	ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelF()

	// Create a test object to be able to later use a test DB.
	t := tests.NewTestObject("mapserver_integration")

	// Configure a test DB.
	dbConf, removeF := testdb.ConfigureTestDB(t)
	defer removeF()

	// Connect to the DB.
	conn := testdb.Connect(t, dbConf)
	// Insert some mock data.
	tup.UpdateDBwithRandomCerts(ctx, t, conn, []string{
		"a.com",
		"b.com",
		"c.com"},
		[]tup.CertsPoliciesOrBoth{
			tup.CertsOnly,
			tup.PoliciesOnly,
			tup.BothCertsAndPolicies,
		})
	err := conn.Close()
	require.NoError(t, err)

	// Create a test configuration for the mapserver.
	conf := &config.Config{
		UpdateTimer:        util.DurationWrap{Duration: 24 * time.Hour},
		UpdateAt:           util.NewTimeOfDay(3, 0, 0, 0),
		CTLogServerURLs:    []string{"https://ct.googleapis.com/logs/xenon2023/"},
		DBConfig:           dbConf,
		CertificatePemFile: "./tests/testdata/servercert.pem",
		PrivateKeyPemFile:  "./tests/testdata/serverkey.pem",
	}

	// Mapserver:
	server, err := mapserver.NewMapServer(ctx, conf)
	check(err)

	// Start serving requests.
	go func() {
		err = server.Listen(context.Background())
		check(err)
	}()

	// Prepare the client.
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{
		Transport: tr,
	}
	resp, err := client.Get("https://localhost:8443/getproof")
	check(err)
	defer resp.Body.Close()

	fmt.Println("Response Status:", resp.Status)

	// Request a.com

	return 0
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
