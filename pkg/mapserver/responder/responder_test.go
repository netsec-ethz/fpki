package responder

import (
	"context"
	"crypto/rsa"
	"encoding/hex"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netsec-ethz/fpki/pkg/common"
	mapcommon "github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/prover"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/netsec-ethz/fpki/pkg/tests/random"
	"github.com/netsec-ethz/fpki/pkg/tests/testdb"
	"github.com/netsec-ethz/fpki/pkg/util"
)

func TestNewResponder(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	// Configure a test DB.
	config, removeF := testdb.ConfigureTestDB(t)
	defer removeF()

	// Connect to the DB.
	conn, err := testdb.Connect(config)
	require.NoError(t, err)
	defer conn.Close()

	// Create a responder (root will be nil).
	responder, err := NewMapResponder(ctx, conn, loadKey(t, "testdata/server_key.pem"))
	require.NoError(t, err)
	// Check its tree head is nil.
	require.Nil(t, responder.smt.Root)
	// Check its STH is not nil.
	sth := responder.SignedTreeHead()
	require.Equal(t, 8*common.SHA256Size, len(sth),
		"bad length of STH: %s", hex.EncodeToString(sth))

	// Repeat test with a non nil root.
	// Insert a mockup root.
	root := common.SHA256Hash32Bytes([]byte{0})
	err = conn.SaveRoot(ctx, &root)
	require.NoError(t, err)
	// Create a responder (root will NOT be nil).
	responder, err = NewMapResponder(ctx, conn, loadKey(t, "testdata/server_key.pem"))
	require.NoError(t, err)
	// Check its tree head is NOT nil.
	require.NotNil(t, responder.smt.Root)
	// Check its STH is not nil.
	sth2 := responder.SignedTreeHead()
	require.Equal(t, 8*common.SHA256Size, len(sth2),
		"bad length of STH: %s", hex.EncodeToString(sth2))
}

// TestProofWithPoP checks for 3 domains: a.com (certs), b.com (policies), c.com (both),
// that the proofs of presence work correctly, by ingesting all the material, updating the DB,
// creating a responder, and checking those domains.
func TestProof(t *testing.T) {
	// Because we are using "random" bytes deterministically here, set a fixed seed.
	rand.Seed(1)

	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	// Configure a test DB.
	config, removeF := testdb.ConfigureTestDB(t)
	defer removeF()

	// Connect to the DB.
	conn, err := testdb.Connect(config)
	require.NoError(t, err)
	defer conn.Close()

	// a.com
	certs, certIDs, parentCertIDs, names := random.BuildTestRandomCertHierarchy(t, "a.com")
	err = updater.UpdateWithKeepExisting(ctx, conn, names, certIDs, parentCertIDs, certs,
		util.ExtractExpirations(certs), nil)
	require.NoError(t, err)
	certsA := certs

	// b.com
	policies := random.BuildTestRandomPolicyHierarchy(t, "b.com")
	err = updater.UpdateWithKeepExisting(ctx, conn, nil, nil, nil, nil, nil, policies)
	require.NoError(t, err)
	policiesB := policies

	// c.com
	certs, certIDs, parentCertIDs, names = random.BuildTestRandomCertHierarchy(t, "c.com")
	policies = random.BuildTestRandomPolicyHierarchy(t, "c.com")
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
	responder, err := NewMapResponder(ctx, conn, loadKey(t, "testdata/server_key.pem"))
	require.NoError(t, err)

	// Check a.com:
	proofChain, err := responder.GetProof(ctx, "a.com")
	require.NoError(t, err)
	id := common.SHA256Hash32Bytes(certsA[0].Raw)
	checkProof(t, &id, proofChain)

	// Check b.com:
	proofChain, err = responder.GetProof(ctx, "b.com")
	require.NoError(t, err)
	id = common.SHA256Hash32Bytes(policiesB[0].Raw())
	checkProof(t, &id, proofChain)

	// Check c.com:
	proofChain, err = responder.GetProof(ctx, "c.com")
	require.NoError(t, err)
	id = common.SHA256Hash32Bytes(certsC[0].Raw)
	checkProof(t, &id, proofChain)

	// Now check an absent domain.
	proofChain, err = responder.GetProof(ctx, "absentdomain.domain")
	require.NoError(t, err)
	checkProof(t, nil, proofChain)
}

// checkProof checks the proof to be correct.
func checkProof(t *testing.T, payloadID *common.SHA256Output, proofs []*mapcommon.MapServerResponse) {
	t.Helper()
	// Determine if we are checking an absence or presence.
	if payloadID == nil {
		// Absence.
		require.Equal(t, mapcommon.PoA, proofs[len(proofs)-1].PoI.ProofType, "PoA not found")
	} else {
		// Check the last component is present.
		require.Equal(t, mapcommon.PoP, proofs[len(proofs)-1].PoI.ProofType, "PoP not found")
	}
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

func loadKey(t tests.T, filename string) *rsa.PrivateKey {
	k, err := util.RSAKeyFromPEMFile(filename)
	require.NoError(t, err)
	return k
}
