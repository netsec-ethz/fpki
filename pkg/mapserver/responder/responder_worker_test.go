package responder

import (
	"bytes"
	"context"
	"io/ioutil"
	"strings"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/internal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netsec-ethz/fpki/pkg/common"
	mapCommon "github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/prover"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
)

// TestGetDomainProof: test getDomainProof()
func TestGetDomainProof(t *testing.T) {
	certs := []*x509.Certificate{}

	// load test certs
	files, err := ioutil.ReadDir("../updater/testdata/certs/")
	require.NoError(t, err)

	for _, file := range files {
		cert, err := common.CTX509CertFromFile("../updater/testdata/certs/" + file.Name())
		require.NoError(t, err)
		certs = append(certs, cert)
	}

	// update the certificates in a mock updater, then return the mock db
	smtDB, updaterDB, root, err := getUpdatedUpdater(certs)
	require.NoError(t, err)

	smt, err := trie.NewTrie(root, common.SHA256Hash, smtDB)
	require.NoError(t, err)

	// init a new responder worker
	responderWorker := responderWorker{
		smt:    smt,
		dbConn: updaterDB,
	}

	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	for _, cert := range certs {
		proofs, err := responderWorker.getDomainProof(ctx, cert.Subject.CommonName)
		require.NoError(t, err)

		assert.True(t, checkProof(*cert, proofs))
	}
}

// get one updater using mockdb, update the certificates and return the mockdb
func getUpdatedUpdater(certs []*x509.Certificate) (db.Conn, db.Conn, []byte, error) {
	smtDB := internal.NewMockDB()
	smt, err := trie.NewTrie(nil, common.SHA256Hash, smtDB)
	if err != nil {
		return nil, nil, nil, err
	}

	smt.CacheHeightLimit = 233

	updaterDB := internal.NewMockDB()
	updater, err := getMockUpdater(smt, updaterDB)
	if err != nil {
		return nil, nil, nil, err
	}

	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	// update the db using the certs
	err = updater.UpdateCerts(ctx, certs)
	if err != nil {
		return nil, nil, nil, err
	}

	err = updater.CommitSMTChanges(ctx)
	if err != nil {
		return nil, nil, nil, err
	}

	return smtDB, updaterDB, updater.SMT().Root, nil
}

// get a updater using mock db
func getMockUpdater(smt *trie.Trie, updaterDB *internal.MockDB) (*updater.UpdaterTestAdapter, error) {
	updater := &updater.UpdaterTestAdapter{}
	updater.SetDBConn(updaterDB)
	updater.SetSMT(smt)
	return updater, nil
}

// check if the proof is correct, provided the certificate
func checkProof(cert x509.Certificate, proofs []mapCommon.MapServerResponse) bool {
	caName := cert.Issuer.CommonName
	for _, proof := range proofs {
		if !strings.Contains(cert.Subject.CommonName, proof.Domain) {
			return false
		}
		proofType, isCorrect, err := prover.VerifyProofByDomain(proof)
		if err != nil {
			return false
		}

		if !isCorrect {
			return false
		}

		if proofType == mapCommon.PoA {
			if len(proof.DomainEntryBytes) != 0 {
				return false
			}
		}
		if proofType == mapCommon.PoP {
			domainEntry, err := mapCommon.DeserializeDomainEntry(proof.DomainEntryBytes)
			if err != nil {
				return false
			}
			// get the correct CA entry
			for _, caEntry := range domainEntry.CAEntry {
				if caEntry.CAName == caName {
					// check if the cert is in the CA entry
					for _, certRaw := range caEntry.DomainCerts {
						if bytes.Equal(certRaw, cert.Raw) {
							return true
						}
					}
				}
			}
		}
	}
	return false
}
