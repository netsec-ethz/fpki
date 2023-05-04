package responder

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/db/mysql"
	mapcommon "github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/prover"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	"github.com/netsec-ethz/fpki/pkg/tests/testdb"
	"github.com/netsec-ethz/fpki/pkg/util"
)

// TestProofWithPoP checks for 3 domains: a.com (certs), b.com (policies), c.com (both),
// that the proofs of presence work correctly, by ingesting all the material, updating the DB,
// creating a responder, and checking those domains.
func TestProofWithPoP(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	// DB will have the same name as the test function.
	dbName := t.Name()
	config := db.NewConfig(mysql.WithDefaults(), db.WithDB(dbName))

	// Create a new DB with that name. On exiting the function, it will be removed.
	err := testdb.CreateTestDB(ctx, dbName)
	require.NoError(t, err)
	defer func() {
		err = testdb.RemoveTestDB(ctx, config)
		require.NoError(t, err)
	}()

	// Connect to the DB.
	conn, err := mysql.Connect(config)
	require.NoError(t, err)
	defer conn.Close()

	// a.com
	certs, certIDs, parentCertIDs, names := testdb.BuildTestCertHierarchy(t, "a.com")
	err = updater.UpdateWithKeepExisting(ctx, conn, names, certIDs, parentCertIDs, certs,
		util.ExtractExpirations(certs), nil)
	require.NoError(t, err)
	certsA := certs

	// b.com
	policies := testdb.BuildTestPolicyHierarchy(t, "b.com")
	err = updater.UpdateWithKeepExisting(ctx, conn, nil, nil, nil, nil, nil, policies)
	require.NoError(t, err)
	policiesB := policies

	// c.com
	certs, certIDs, parentCertIDs, names = testdb.BuildTestCertHierarchy(t, "c.com")
	policies = testdb.BuildTestPolicyHierarchy(t, "c.com")
	err = updater.UpdateWithKeepExisting(ctx, conn, names, certIDs, parentCertIDs, certs,
		util.ExtractExpirations(certs), policies)
	require.NoError(t, err)
	certsC := certs

	// Coalescing of payloads.
	err = updater.CoalescePayloadsForDirtyDomains(ctx, conn)
	require.NoError(t, err)

	// Create/update the SMT.
	err = updater.UpdateSMT(ctx, conn, 32)
	require.NoError(t, err)

	// And cleanup dirty, flagging the end of the update cycle.
	err = conn.CleanupDirty(ctx)
	require.NoError(t, err)

	// Create a responder.
	responder, err := NewMapResponder(ctx, "./testdata/mapserver_config.json", conn)
	require.NoError(t, err)

	// Check a.com:
	proofChain, err := responder.GetProof(ctx, "a.com")
	assert.NoError(t, err)
	id := common.SHA256Hash32Bytes(certsA[0].Raw)
	checkProof(t, &id, proofChain)

	// Check b.com:
	proofChain, err = responder.GetProof(ctx, "b.com")
	assert.NoError(t, err)
	id = common.SHA256Hash32Bytes(policiesB[0].Raw())
	checkProof(t, &id, proofChain)

	// Check b.com:
	proofChain, err = responder.GetProof(ctx, "c.com")
	assert.NoError(t, err)
	id = common.SHA256Hash32Bytes(certsC[0].Raw)
	checkProof(t, &id, proofChain)
}

// checkProof checks the proof to be correct.
func checkProof(t *testing.T, payloadID *common.SHA256Output, proofs []*mapcommon.MapServerResponse) {
	t.Helper()
	require.Equal(t, mapcommon.PoP, proofs[len(proofs)-1].PoI.ProofType, "PoP not found")
	for _, proof := range proofs {
		proofType, isCorrect, err := prover.VerifyProofByDomain(proof)
		require.NoError(t, err)
		require.True(t, isCorrect)

		if proofType == mapcommon.PoA {
			require.Empty(t, proof.DomainEntry.CertIDs)
			require.Empty(t, proof.DomainEntry.PolicyIDs)
		}
		if proofType == mapcommon.PoP {
			// The ID passed as argument must be one of the IDs present in the domain entry.
			allIDs := append(common.BytesToIDs(proof.DomainEntry.CertIDs),
				common.BytesToIDs(proof.DomainEntry.PolicyIDs)...)
			require.Contains(t, allIDs, payloadID)
		}
	}
}
