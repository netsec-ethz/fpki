package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/db/mysql"
	"github.com/netsec-ethz/fpki/pkg/mapserver/responder"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	"github.com/netsec-ethz/fpki/pkg/util"
	testdb "github.com/netsec-ethz/fpki/tests/pkg/db"
)

const (
	BatchSize = 1000
	DBName    = "mapServerIT"
)

func main() {
	os.Exit(mainFunc())
}

func mainFunc() int {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	// Create an empty test DB
	err := testdb.CreateTestDB(ctx, DBName)
	config := db.NewConfig(mysql.WithDefaults(), db.WithDB(DBName))
	panicIfError(err)
	defer func() {
		err := testdb.RemoveTestDB(ctx, *config)
		panicIfError(err)
	}()

	// Test connect several times.
	conn, err := mysql.Connect(config)
	panicIfError(err)
	panicIfError(conn.Close())
	conn, err = mysql.Connect(config)
	panicIfError(err)
	panicIfError(conn.Close())

	// Ingest data.
	ingestData(ctx, config)

	// Get some proofs.
	retrieveSomeProofs(ctx, config)

	// Compare expected results
	return 0
}

func ingestData(ctx context.Context, config *db.Configuration) {
	// Connect to the test DB
	conn, err := mysql.Connect(config)
	panicIfError(err)
	defer func() {
		fmt.Println("deleteme closing")
		err := conn.Close()
		panicIfError(err)
	}()

	// Ingest the testdata.
	raw, err := util.ReadAllGzippedFile("./tests/testdata/2-xenon2023.csv.gz")
	panicIfError(err)
	payloads, IDs, parentIDs, names, err := util.LoadCertsAndChainsFromCSV(raw)
	panicIfError(err)

	// Insert the certificates into the test DB in batches.
	expirations := util.ExtractExpirations(payloads)
	for i := 0; i < (len(names) / BatchSize); i++ {
		b := i * BatchSize       // begin
		e := (i + 1) * BatchSize // end
		err = updater.UpdateCertsWithKeepExisting(ctx, conn, names[b:e], expirations[b:e],
			payloads[b:e], IDs[b:e], parentIDs[b:e])
		panicIfError(err)
	}
	// Remainder of the certificates
	b := (len(names) / BatchSize) * BatchSize
	err = updater.UpdateCertsWithKeepExisting(ctx, conn, names[b:], expirations[b:],
		payloads[b:], IDs[b:], parentIDs[b:])
	panicIfError(err)

	err = updater.CoalescePayloadsForDirtyDomains(ctx, conn, 2)
	panicIfError(err)
}

func retrieveSomeProofs(ctx context.Context, config *db.Configuration) {
	// Connect to the test DB
	conn, err := mysql.Connect(config)
	panicIfError(err)

	// Retrieve some domains
	res, err := responder.NewMapResponder(ctx, "./config/mapserver_config.json", conn)
	panicIfError(err)
	p, err := res.GetProof(ctx, "aname.com")
	panicIfError(err)
	_ = p
}

func panicIfError(err error) {
	if err != nil {
		panic(err)
	}
}
