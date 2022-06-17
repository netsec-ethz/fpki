package benchmark

import (
	"bytes"
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	ctX509 "github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/logpicker"
	"github.com/netsec-ethz/fpki/pkg/mapserver/prover"
	"github.com/netsec-ethz/fpki/pkg/mapserver/responder"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	"github.com/stretchr/testify/require"
)

func TestResponder(t *testing.T) {
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
	responder, err := responder.NewMapResponder(ctx, root, 233, 10)
	require.NoError(t, err)
	for _, cert := range certs {
		responses, err := responder.GetProof(ctx, cert.Subject.CommonName)
		require.NoError(t, err)

		require.True(t, checkProof(*cert, responses))
		/*
			for _, r := range responses {
				t.Logf("%v : %s", r.PoI.ProofType, cert.Subject.CommonName)
				require.Equal(t, common.PoP, r.PoI.ProofType,
					"PoP not found for %s", r.Domain)
			}*/
	}
}

func checkProof(cert ctX509.Certificate, proofs []common.MapServerResponse) bool {
	caName := cert.Issuer.CommonName
	for _, proof := range proofs {
		if !strings.Contains(cert.Subject.CommonName, proof.Domain) {
			panic("wrong domain proofs")
		}
		proofType, isCorrect, err := prover.VerifyProofByDomain(proof)
		if err != nil {
			panic(err)
		}

		if !isCorrect {
			panic("wrong proof")
		}

		if proofType == common.PoA {
			if len(proof.DomainEntryBytes) != 0 {
				panic("domain entry bytes not empty for PoA")
			}
		}
		if proofType == common.PoP {
			domainEntry, err := common.DeserializeDomainEntry(proof.DomainEntryBytes)
			if err != nil {
				panic(err)
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
