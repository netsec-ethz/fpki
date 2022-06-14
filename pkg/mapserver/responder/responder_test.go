package responder

import (
	"context"
	"io/ioutil"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
	"github.com/stretchr/testify/assert"
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

		assert.True(t, checkProof(*cert, proofs))
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
