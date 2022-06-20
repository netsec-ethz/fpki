package responder

import (
	"context"
	"database/sql"
	"io/ioutil"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/common"
	mapcommon "github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/logpicker"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	"github.com/stretchr/testify/require"
)

// TestGetProof: test GetProof()
func TestGetProof(t *testing.T) {
	certs := []*x509.Certificate{}

	// load test certs
	files, err := ioutil.ReadDir("../updater/testdata/certs/")
	require.NoError(t, err)

	for _, file := range files {
		cert, err := common.CTX509CertFromFile("../updater/testdata/certs/" + file.Name())
		require.NoError(t, err)
		certs = append(certs, cert)
	}

	// get mock responder
	responder, err := getMockResponder(certs)
	require.NoError(t, err)

	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	for _, cert := range certs {
		proofs, err := responder.GetProof(ctx, cert.Subject.CommonName)
		require.NoError(t, err)

		checkProof(t, *cert, proofs)
	}
}

func TestResponderWithPoP(t *testing.T) {
	// truncate tables
	db, err := sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/fpki?maxAllowedPacket=1073741824")
	if err != nil {
		panic(err)
	}

	_, err = db.Exec("TRUNCATE domainEntries;")
	if err != nil {
		panic(err)
	}

	_, err = db.Exec("TRUNCATE updates;")
	if err != nil {
		panic(err)
	}

	_, err = db.Exec("TRUNCATE tree;")
	if err != nil {
		panic(err)
	}

	mapUpdater, err := updater.NewMapUpdater(nil, 233)
	require.NoError(t, err)
	ctx, cancelF := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancelF()

	mapUpdater.Fetcher.BatchSize = 10000
	const baseCTSize = 2 * 1000
	const count = 2
	mapUpdater.StartFetching("https://ct.googleapis.com/logs/argon2021",
		baseCTSize, baseCTSize+count-1)

	n, err := mapUpdater.UpdateNextBatch(ctx)
	require.NoError(t, err)
	require.Equal(t, n, count)

	n, err = mapUpdater.UpdateNextBatch(ctx)
	require.NoError(t, err)
	require.Equal(t, n, 0)

	err = mapUpdater.CommitSMTChanges(ctx)
	require.NoError(t, err)

	root := mapUpdater.GetRoot()
	err = mapUpdater.Close()
	require.NoError(t, err)

	// manually get those certificates and make a list of the common names
	// https://ct.googleapis.com/logs/argon2021/ct/v1/get-entries?start=2000&end=2001
	fetcher := logpicker.LogFetcher{
		URL:         "https://ct.googleapis.com/logs/argon2021",
		Start:       baseCTSize,
		End:         baseCTSize + count - 1,
		WorkerCount: 1,
		BatchSize:   20,
	}
	certs, err := fetcher.FetchAllCertificates(ctx)
	require.NoError(t, err)
	require.Len(t, certs, count)

	// create responder and request proof for those names
	responder, err := NewMapResponder(ctx, root, 233, 10)
	require.NoError(t, err)
	for _, cert := range certs {
		responses, err := responder.GetProof(ctx, cert.Subject.CommonName)
		require.NoError(t, err)

		for _, r := range responses {
			t.Logf("%v : %s", r.PoI.ProofType, r.Domain)
		}

		require.NotEmpty(t, responses)
		checkProof(t, *cert, responses)
		// ensure that the response for the whole name is a PoP
		require.Equal(t, mapcommon.PoP, responses[len(responses)-1].PoI.ProofType,
			"PoP not found for %s", cert.Subject.CommonName)
	}
}

// get a mock responder
func getMockResponder(certs []*x509.Certificate) (*MapResponder, error) {
	// update the certs, and get the mock db of SMT and db
	smtDB, updaterDB, root, err := getUpdatedUpdater(certs)

	smt, err := trie.NewTrie(root, common.SHA256Hash, smtDB)
	if err != nil {
		return nil, err
	}
	smt.CacheHeightLimit = 233

	clientInputChan := make(chan ClientRequest)
	workerPool := make([]*responderWorker, 0, 3)

	// create worker pool
	for i := 0; i < 3; i++ {
		newWorker := &responderWorker{
			dbConn:          updaterDB,
			clientInputChan: clientInputChan,
			smt:             smt,
		}
		workerPool = append(workerPool, newWorker)
		go newWorker.work()
	}

	responder := &MapResponder{
		workerPool: workerPool,
		workerChan: clientInputChan,
		smt:        smt,
	}

	return responder, nil
}
