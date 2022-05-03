package main

import (
	"crypto/sha256"
	"os"
	"path"
	"strconv"
	"testing"

	"github.com/celestiaorg/smt"
	"github.com/netsec-ethz/fpki/pkg/mapserver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMapServer: Update some domains -> retrieve domains' proof -> validate them
func TestMapServer(t *testing.T) {
	tempFile := path.Join(os.TempDir(), "root")
	defer os.Remove(tempFile)

	// init a updator
	updator, err := mapserver.NewUpdator(tempFile)
	require.NoError(t, err, "New Updator error")

	testData := make(map[string][]byte)
	for i := 1; i < 4; i++ {
		testData[strconv.Itoa(i)] = []byte(`hi this is a small test. Today is Tuesday. We have a small 
		meeting and it's a good meeting. I meet some new friends.`)
	}

	for k, v := range testData {
		err = updator.UpdateDomain(k, v)
		require.NoError(t, err, "Update Domain error")
	}

	// write root
	root := updator.Root()
	f, err := os.Create(tempFile)
	require.NoError(t, err, "Create file error")

	_, err = f.Write(root)
	require.NoError(t, err, "Write file error")

	err = f.Close()
	require.NoError(t, err, "Close file error")

	// load an responder
	responder, err := mapserver.NewResponder(tempFile)
	require.NoError(t, err, "New Responder error")

	for k, v := range testData {
		queryResults, err := responder.QueryDomain(k)
		require.NoError(t, err, "Query Domain error")

		result := smt.VerifyProof(queryResults.Proof, root, []byte(k), v, sha256.New())
		assert.Equal(t, result, true, "verification error")
	}

	updator.Close()
	responder.Close()
}
