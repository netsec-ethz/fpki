package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver"
	mapcommon "github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/config"
	"github.com/netsec-ethz/fpki/pkg/mapserver/prover"
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
	certs, policies, _, _, _ := tup.UpdateDBwithRandomCerts(ctx, t, conn, []string{
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
	// Ancilliary test to check that UpdateDBwithRandomCerts worked as expected.
	require.Equal(t, 8, len(certs))    // a.com and c.com
	require.Equal(t, 4, len(policies)) // b.com and c.com

	// Create a test configuration for the mapserver.
	conf := &config.Config{
		UpdateTimer:        util.DurationWrap{Duration: 24 * time.Hour},
		UpdateAt:           util.NewTimeOfDay(3, 0, 0, 0),
		CTLogServerURLs:    []string{"https://invalid.netsec.ethz.ch"},
		DBConfig:           dbConf,
		CertificatePemFile: "./tests/testdata/servercert.pem",
		PrivateKeyPemFile:  "./tests/testdata/serverkey.pem",
	}

	// Mapserver:
	server, err := mapserver.NewMapServer(ctx, conf)
	require.NoError(t, err)
	// Start serving requests.
	go func() {
		err = server.Listen(ctx)
		require.NoError(t, err)
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

	rawPolicies := make([][]byte, len(policies))
	for i, p := range policies {
		raw, err := p.Raw()
		require.NoError(t, err)
		rawPolicies[i] = raw
	}
	// Check responses for a.com, b.com and c.com .
	checkResponse(t, client, "a.com", []common.SHA256Output{
		common.SHA256Hash32Bytes(certs[0].Raw),
		common.SHA256Hash32Bytes(certs[1].Raw),
		common.SHA256Hash32Bytes(certs[2].Raw),
		common.SHA256Hash32Bytes(certs[3].Raw),
	})
	checkResponse(t, client, "b.com", []common.SHA256Output{
		common.SHA256Hash32Bytes(rawPolicies[0]),
		common.SHA256Hash32Bytes(rawPolicies[1]),
	})
	checkResponse(t, client, "c.com", []common.SHA256Output{
		common.SHA256Hash32Bytes(certs[4].Raw),
		common.SHA256Hash32Bytes(certs[5].Raw),
		common.SHA256Hash32Bytes(certs[6].Raw),
		common.SHA256Hash32Bytes(certs[7].Raw),
		common.SHA256Hash32Bytes(rawPolicies[2]),
		common.SHA256Hash32Bytes(rawPolicies[3]),
	})

	return 0
}

func checkResponse(
	t tests.T,
	client *http.Client,
	domainName string,
	ids []common.SHA256Output,
) {

	// Proof of inclusion.
	t.Logf("verifying inclusion of %s", domainName)
	resp, err := client.Get(fmt.Sprintf("https://localhost:%d/getproof?domain=%s",
		mapserver.APIPort,
		domainName,
	))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	dec := json.NewDecoder(resp.Body)
	var proofChain []*mapcommon.MapServerResponse
	err = dec.Decode(&proofChain)
	require.NoError(t, err)
	resp.Body.Close()

	for _, id := range ids {
		checkProof(t, &id, proofChain)
	}
	checkIDsInProof(t, proofChain, ids)

	// Now distinguish between cert and policy IDs before requesting payloads.
	certIDs := make(map[common.SHA256Output]struct{})
	policyIDs := make(map[common.SHA256Output]struct{})
	for _, p := range proofChain {
		for _, id := range common.BytesToIDs(p.DomainEntry.CertIDs) {
			certIDs[*id] = struct{}{}
		}
		for _, id := range common.BytesToIDs(p.DomainEntry.PolicyIDs) {
			policyIDs[*id] = struct{}{}
		}
	}

	grouping := []struct {
		fcn string
		ids map[common.SHA256Output]struct{}
	}{
		{
			fcn: "getcertpayloads",
			ids: certIDs,
		},
		{
			fcn: "getpolicypayloads",
			ids: policyIDs,
		},
	}
	// Get all payloads:
	for _, group := range grouping {
		if len(group.ids) == 0 {
			continue
		}
		var collatedIDs string
		for id := range group.ids {
			collatedIDs += hex.EncodeToString(id[:])
		}
		resp, err = client.Get(fmt.Sprintf("https://localhost:%d/%s?ids=%s",
			mapserver.APIPort,
			group.fcn,
			collatedIDs,
		))
		require.NoError(t, err)
		respBytes, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode, string(respBytes))
		dec := json.NewDecoder(bytes.NewReader(respBytes))
		var payloads [][]byte
		err = dec.Decode(&payloads)
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, len(group.ids), len(payloads))
		// Check the payloads by checking their hashes are the same.
		computedIDs := make(map[common.SHA256Output]struct{})
		for _, payload := range payloads {
			id := common.SHA256Hash32Bytes(payload)
			computedIDs[id] = struct{}{}
		}
		require.EqualValues(t, group.ids, computedIDs)
	}
}

// checkProof checks the proof to be correct.
func checkProof(t tests.T, payloadID *common.SHA256Output, proofs []*mapcommon.MapServerResponse) {
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

// checkIDsInProof verifies that the IDs contained in the proof chain are the same as those
// expected (not just included, but the same set of IDs).
func checkIDsInProof(
	t tests.T,
	proofChain []*mapcommon.MapServerResponse,
	IDs []common.SHA256Output) {

	// Extract all IDs from the proof chain.
	allIDs := make(map[common.SHA256Output]struct{})
	for i := range proofChain {
		// Certificates.
		ids := common.BytesToIDs(proofChain[i].DomainEntry.CertIDs)
		for _, id := range ids {
			allIDs[*id] = struct{}{}
		}
		// Policies.
		ids = common.BytesToIDs(proofChain[i].DomainEntry.PolicyIDs)
		for _, id := range ids {
			allIDs[*id] = struct{}{}
		}
	}

	// Create a set with all the expected IDs.
	expected := make(map[common.SHA256Output]struct{})
	for _, id := range IDs {
		expected[id] = struct{}{}
	}

	require.EqualValues(t, expected, allIDs)
}
