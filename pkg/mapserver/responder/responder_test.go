package responder

import (
	"context"
	"testing"
	"time"

	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/db/mysql"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/netsec-ethz/fpki/pkg/util"
	"github.com/stretchr/testify/require"
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
	require.NoError(t, err)
	certs, IDs, parentIDs, names, err := util.LoadCertsAndChainsFromCSV(raw)
	require.NoError(t, err)
	err = updater.UpdateCertsWithKeepExisting(ctx, conn, names, util.ExtractExpirations(certs),
		certs, IDs, parentIDs)
	require.NoError(t, err)

	// Final stage of ingestion: coalescing of payloads.
	err = updater.CoalescePayloadsForDirtyDomains(ctx, conn, 1)
	require.NoError(t, err)

	// // Create a responder.
	// responder, err := NewMapResponder(ctx, "./testdata/mapserver_config.json", conn)
	// require.NoError(t, err)

	// // Log the names of the certs.
	// for i, names := range names {
	// 	t.Logf("cert %d for the following names:\n", i)
	// 	for j, name := range names {
	// 		t.Logf("\t[%3d]: \"%s\"\n", j, name)
	// 	}
	// 	if len(names) == 0 {
	// 		t.Log("\t[no names]")
	// 	}
	// }

	// // Check proofs for the previously ingested certificates.
	// for i, c := range certs {
	// 	if names[i] == nil {
	// 		// This is a non leaf certificate, skip.
	// 		continue
	// 	}
	// 	for _, name := range names[i] {
	// 		t.Logf("proof for %s\n", name)
	// 		proofChain, err := responder.GetProof(ctx, name)
	// 		assert.NoError(t, err)
	// 		if err == nil {
	// 			checkProof(t, c, proofChain)
	// 		}
	// 	}
	// }
}
