package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	certs, _, _, _, _ := tup.UpdateDBwithRandomCerts(ctx, t, conn, []string{
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

	// Request a.com => it is at certs[2] and certs[3]
	idA1 := common.SHA256Hash32Bytes(certs[2].Raw)
	idA2 := common.SHA256Hash32Bytes(certs[3].Raw)
	// 1. Proof
	resp, err := client.Get(fmt.Sprintf("https://localhost:%d/getproof?domain=a.com",
		mapserver.APIPort))
	require.NoError(t, err)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	dec := json.NewDecoder(resp.Body)
	var proofChain []*mapcommon.MapServerResponse
	err = dec.Decode(&proofChain)
	require.NoError(t, err)
	resp.Body.Close()
	checkProof(t, &idA1, proofChain)
	checkProof(t, &idA2, proofChain)

	// 2. Payloads
	resp, err = client.Get(fmt.Sprintf("https://localhost:%d/getpayloads?ids="+
		hex.EncodeToString(idA1[:])+hex.EncodeToString(idA2[:]),
		mapserver.APIPort))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	dec = json.NewDecoder(resp.Body)
	var payloads [][]byte
	err = dec.Decode(&payloads)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, 2, len(payloads))
	// Check they are the same.
	require.Equal(t, certs[2].Raw, payloads[0])
	require.Equal(t, certs[3].Raw, payloads[1])

	fmt.Println("OK")
	return 0
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
