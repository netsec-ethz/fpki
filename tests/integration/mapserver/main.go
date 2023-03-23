package main

import (
	"context"
	"fmt"
	"os"
	"time"

	ctx509 "github.com/google/certificate-transparency-go/x509"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/db/mysql"
	"github.com/netsec-ethz/fpki/pkg/mapserver/responder"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	"github.com/netsec-ethz/fpki/pkg/util"
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

	config := db.NewConfig(mysql.WithDefaults(), db.WithDB(DBName))

	// // Create an empty test DB
	// err := tests.CreateTestDB(ctx, DBName)
	// panicIfError(err)
	// defer func() {
	// 	err := tests.RemoveTestDB(ctx, config)
	// 	panicIfError(err)
	// }()
	// fmt.Printf("created DB %s.\n", DBName)

	// // Test connect several times.
	// conn, err := mysql.Connect(config)
	// panicIfError(err)
	// panicIfError(conn.Close())
	// conn, err = mysql.Connect(config)
	// panicIfError(err)
	// panicIfError(conn.Close())
	// fmt.Println("done testing the DB connection.")

	// // Ingest data.
	// ingestData(ctx, config)
	// fmt.Println("done ingesting test data.")

	// Get a responder.
	res := getResponder(ctx, config)
	fmt.Println("done loading a responder.")

	// Compare proofs against expected results.
	data := getSomeDataPointsToTest(ctx, config)
	errors := false
	for _, d := range data {
		fmt.Printf("checking %s ... ", d.Name)
		proof, err := res.GetProof(ctx, d.Name)
		panicIfError(err)
		fmt.Printf("has %d steps\n", len(proof))
		// Present domains will surely have certificates.
		for _, c := range d.Certs {
			err = util.CheckProof(proof, d.Name, c)
			if err != nil {
				errors = true
				fmt.Printf("error found with %s: %s\n", d.Name, err)
			}
		}
	}
	if errors {
		return 1
	}

	return 0
}

func ingestData(ctx context.Context, config *db.Configuration) {
	// Connect to the test DB
	conn, err := mysql.Connect(config)
	panicIfError(err)
	defer func() {
		panicIfError(conn.Close())
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

	// Build the domain_payloads entries from dirty.
	err = updater.CoalescePayloadsForDirtyDomains(ctx, conn, 2)
	panicIfError(err)

	// Do the SMT update.
	err = updater.UpdateSMT(ctx, conn, 32)
	panicIfError(err)
}

func getResponder(ctx context.Context, config *db.Configuration) *responder.MapResponder {
	// Connect to the test DB
	conn, err := mysql.Connect(config)
	panicIfError(err)

	// Retrieve some domains
	res, err := responder.NewMapResponder(
		ctx,
		"./tests/integration/mapserver/config/mapserver_config.json",
		conn)
	panicIfError(err)
	return res
}

type DataPoint struct {
	Name  string
	Certs []*ctx509.Certificate
}

func getSomeDataPointsToTest(ctx context.Context, config *db.Configuration) []DataPoint {
	// Connect to the test DB
	conn, err := mysql.Connect(config)
	panicIfError(err)
	defer func() {
		panicIfError(conn.Close())
	}()

	// Some names from the test DB.
	names := []string{
		// (4568 certs),
		"*.us-west-2.es.amazonaws.com",

		// (2198 certs),
		"flowers-to-the-world.com",

		// (1 cert),
		"vg01.sjc006.ix.nflxvideo.net",

		// (0 certs),
		"doesnnotexist.iamsure.of.that.ch",
	}

	// Find certificates for these names.
	data := make([]DataPoint, len(names))
	for i, name := range names {
		data[i].Name = name
		ID := common.SHA256Hash32Bytes([]byte(name))
		payload, err := conn.RetrieveDomainEntry(ctx, ID)
		panicIfError(err)
		// payload contains several certificates.
		data[i].Certs, err = ctx509.ParseCertificates(payload)
		panicIfError(err)
		fmt.Printf("found %d certs for %s\n", len(data[i].Certs), name)
	}
	return data
}

func panicIfError(err error) {
	if err != nil {
		panic(err)
	}
}
