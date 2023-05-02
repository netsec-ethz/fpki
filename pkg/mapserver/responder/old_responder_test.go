package responder

import (
	"context"
	"io/ioutil"
	"testing"
	"time"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/db/mysql"
	mapcommon "github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/logpicker"
	"github.com/netsec-ethz/fpki/pkg/mapserver/prover"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	"github.com/netsec-ethz/fpki/pkg/tests/testdb"
	"github.com/stretchr/testify/require"
)

// TestGetProof: test GetProof()
func TestOldGetProof(t *testing.T) {
	return

	certs := []*ctx509.Certificate{}

	// load test certs
	files, err := ioutil.ReadDir("../updater/testdata/certs/")
	require.NoError(t, err)

	for _, file := range files {
		cert, err := common.CTX509CertFromFile("../updater/testdata/certs/" + file.Name())
		require.NoError(t, err)
		certs = append(certs, cert)
	}

	// get mock responder
	responder := getMockOldResponder(t, certs)
	require.NoError(t, err)

	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	for _, cert := range certs {
		proofs, err := responder.GetProof(ctx, cert.Subject.CommonName)
		require.NoError(t, err)

		checkProofOld(t, *cert, proofs)
	}
}

func TestOldResponderWithPoP(t *testing.T) {
	return

	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	dbName := t.Name()
	config := db.NewConfig(mysql.WithDefaults(), db.WithDB(dbName))

	err := testdb.CreateTestDB(ctx, dbName)
	require.NoError(t, err)
	defer func() {
		err = testdb.RemoveTestDB(ctx, config)
		require.NoError(t, err)
	}()

	mapUpdater, err := updater.NewMapUpdater(config, nil, 233)
	require.NoError(t, err)

	mapUpdater.Fetcher.BatchSize = 10000
	const baseCTSize = 2 * 1000
	const count = 1
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
	responder, err := NewOldMapResponder(ctx, config, root, 233, "./testdata/mapserver_config.json")
	require.NoError(t, err)
	for _, cert := range certs {
		responses, err := responder.GetProof(ctx, cert.Subject.CommonName)
		require.NoError(t, err)

		for _, r := range responses {
			t.Logf("%v : %s", r.PoI.ProofType, r.DomainEntry.DomainName)
		}

		require.NotEmpty(t, responses)
		checkProofOld(t, *cert, responses)
		// ensure that the response for the whole name is a PoP
		require.Equal(t, mapcommon.PoP, responses[len(responses)-1].PoI.ProofType,
			"PoP not found for %s", cert.Subject.CommonName)
	}
}

// TestGetDomainProof: test getDomainProof()
func TestOldGetDomainProof(t *testing.T) {
	return

	certs := []*ctx509.Certificate{}

	// load test certs
	files, err := ioutil.ReadDir("../updater/testdata/certs/")
	require.NoError(t, err)

	for _, file := range files {
		cert, err := common.CTX509CertFromFile("../updater/testdata/certs/" + file.Name())
		require.NoError(t, err)
		certs = append(certs, cert)
	}

	responderWorker := getMockOldResponder(t, certs)

	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	for _, cert := range certs {
		proofs, err := responderWorker.getProof(ctx, cert.Subject.CommonName)
		require.NoError(t, err)

		checkProofOld(t, *cert, proofs)
	}
}

// getMockOldResponder builds a mock responder.
func getMockOldResponder(t require.TestingT, certs []*ctx509.Certificate) *OldMapResponder {
	// update the certs, and get the mock db of SMT and db
	conn, root, err := getUpdatedUpdater(t, certs)
	require.NoError(t, err)

	smt, err := trie.NewTrie(root, common.SHA256Hash, conn)
	require.NoError(t, err)
	smt.CacheHeightLimit = 233

	return newMapResponder(conn, smt)
}

// getUpdatedUpdater builds an updater using a mock db, updates the certificates
// and returns the mock db.
func getUpdatedUpdater(t require.TestingT, certs []*ctx509.Certificate) (db.Conn, []byte, error) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	conn := testdb.NewMockDB()
	smt, err := trie.NewTrie(nil, common.SHA256Hash, conn)
	require.NoError(t, err)
	smt.CacheHeightLimit = 233

	updater := &updater.UpdaterTestAdapter{}
	updater.SetDBConn(conn)
	updater.SetSMT(smt)

	// Update the db using the certs and empty chains:
	emptyChains := make([][]*ctx509.Certificate, len(certs))
	err = updater.UpdateCerts(ctx, certs, emptyChains)
	require.NoError(t, err)

	err = updater.CommitSMTChanges(ctx)
	require.NoError(t, err)

	return conn, updater.SMT().Root, nil
}

func checkProofOld(t *testing.T, cert ctx509.Certificate, proofs []mapcommon.MapServerResponse) {
	t.Helper()
	caName := cert.Issuer.String()
	require.Equal(t, mapcommon.PoP, proofs[len(proofs)-1].PoI.ProofType,
		"PoP not found for %s", cert.Subject.CommonName)
	for _, proof := range proofs {
		require.Contains(t, cert.Subject.CommonName, proof.DomainEntry.DomainName)
		proofType, isCorrect, err := prover.VerifyProofByDomainOld(proof)
		require.NoError(t, err)
		require.True(t, isCorrect)

		if proofType == mapcommon.PoA {
			// require.Empty(t, proof.DomainEntryBytes)
		}
		if proofType == mapcommon.PoP {
			// // get the correct CA entry
			// for _, caEntry := range domainEntry.Entries {
			// 	if caEntry.CAName == caName {
			// 		// check if the cert is in the CA entry
			// 		for _, certRaw := range caEntry.DomainCerts {
			// 			require.Equal(t, certRaw, cert.Raw)
			// 			return
			// 		}
			// 	}
			// }
			_ = caName
			return
		}
	}
	require.Fail(t, "cert/CA not found")
}
