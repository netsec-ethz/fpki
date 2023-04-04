package responder

import (
	"context"
	"strings"
	"testing"
	"time"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/db/mysql"
	"github.com/netsec-ethz/fpki/pkg/domain"
	mapcommon "github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/prover"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/netsec-ethz/fpki/pkg/util"
)

func TestProofWithPoP(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Hour)
	defer cancelF()

	// DB will have the same name as the test function.
	dbName := t.Name()
	config := db.NewConfig(mysql.WithDefaults(), db.WithDB(dbName))

	// Create a new DB with that name. On exiting the function, it will be removed.
	err := tests.CreateTestDB(ctx, dbName)
	require.NoError(t, err)
	// defer func() {
	// 	err = tests.RemoveTestDB(ctx, config)
	// 	require.NoError(t, err)
	// }()

	// Connect to the DB.
	conn, err := mysql.Connect(config)
	require.NoError(t, err)
	defer conn.Close()

	// Ingest two certificates and their chains.
	raw, err := util.ReadAllGzippedFile("../../../tests/testdata/2-xenon2023.csv.gz")
	// raw, err := util.ReadAllGzippedFile("../../../tests/testdata/100K-xenon2023.csv.gz")
	require.NoError(t, err)
	certs, IDs, parentIDs, names, err := util.LoadCertsAndChainsFromCSV(raw)
	require.NoError(t, err)
	err = updater.UpdateCertsWithKeepExisting(ctx, conn, names, util.ExtractExpirations(certs),
		certs, IDs, parentIDs)
	require.NoError(t, err)

	// Coalescing of payloads.
	err = updater.CoalescePayloadsForDirtyDomains(ctx, conn)
	require.NoError(t, err)

	// Final stage: create/update a SMT.
	err = updater.UpdateSMT(ctx, conn, 32)
	require.NoError(t, err)

	// And cleanup dirty, flagging the end of the update cycle.
	err = conn.CleanupDirty(ctx)
	require.NoError(t, err)

	// Now to the test.

	// Create a responder.
	responder, err := NewMapResponder(ctx, "./testdata/mapserver_config.json", conn)
	require.NoError(t, err)

	// Log the names of the certs.
	for i, names := range names {
		t.Logf("cert %d for the following names:\n", i)
		for j, name := range names {
			t.Logf("\t[%3d]: \"%s\"\n", j, name)
		}
		if len(names) == 0 {
			t.Log("\t[no names]")
		}
	}

	// Check proofs for the previously ingested certificates.
	foundValidDomainNames := false
	for i, c := range certs {
		t.Logf("Certificate subject is: \"%s\"", domain.CertSubjectName(c))
		if names[i] == nil {
			// This is a non leaf certificate, skip.
			continue
		}

		for _, name := range names[i] {
			t.Logf("Proving \"%s\"", name)
			if !domain.IsValidDomain(name) {
				t.Logf("Invalid domain name: \"%s\", skipping", name)
				continue
			}
			foundValidDomainNames = true
			proofChain, err := responder.GetProof(ctx, name)
			assert.NoError(t, err)
			if err == nil {
				checkProof(t, c, proofChain)
			}
		}
	}
	require.True(t, foundValidDomainNames, "bad test: not one valid checkable domain name")
}

// checkProof checks the proof to be correct.
func checkProof(t *testing.T, cert *ctx509.Certificate, proofs []*mapcommon.MapServerResponse) {
	t.Helper()
	// caName := cert.Issuer.String()
	require.Equal(t, mapcommon.PoP, proofs[len(proofs)-1].PoI.ProofType,
		"PoP not found for \"%s\"", domain.CertSubjectName(cert))
	for _, proof := range proofs {
		// require.Contains(t, cert.Subject.CommonName, proof.Domain)
		includesDomainName(t, proof.Domain, cert)
		proofType, isCorrect, err := prover.VerifyProofByDomain(proof)
		require.NoError(t, err)
		require.True(t, isCorrect)

		if proofType == mapcommon.PoA {
			require.Empty(t, proof.DomainEntryBytes)
		}
		// if proofType == mapcommon.PoP {
		// 	domainEntry, err := mapcommon.DeserializeDomainEntry(proof.DomainEntryBytes)
		// 	require.NoError(t, err)
		// 	// get the correct CA entry
		// 	for _, caEntry := range domainEntry.CAEntry {
		// 		if caEntry.CAName == caName {
		// 			// check if the cert is in the CA entry
		// 			for _, certRaw := range caEntry.DomainCerts {
		// 				require.Equal(t, certRaw, cert.Raw)
		// 				return
		// 			}
		// 		}
		// 	}
		// }
	}
	// require.Fail(t, "cert/CA not found")
}

// includesDomainName checks that the subDomain appears as a substring of at least one of the
// names in the certificate.
func includesDomainName(t *testing.T, subDomain string, cert *ctx509.Certificate) {
	names := updater.ExtractCertDomains(cert)

	for _, s := range names {
		if strings.Contains(s, subDomain) {
			return
		}
	}
	require.FailNow(t, "the subdomain \"%s\" is not present as a preffix in any of the contained "+
		"names of the certtificate: [%s]", subDomain, strings.Join(names, ", "))
}
