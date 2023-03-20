package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/db/mysql"
	"github.com/netsec-ethz/fpki/pkg/mapserver/responder"
	testdb "github.com/netsec-ethz/fpki/tests/pkg/db"
)

func main() {
	os.Exit(mainFunc())
}

func mainFunc() int {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	// Create an empty test DB
	dbName := "testo"
	err := testdb.CreateTestDB(ctx, dbName)
	panicIfError(err)

	// Connect to the test DB
	// Connect to DB via local socket, should be faster.
	config := db.ConfigFromEnvironment()
	// config.Dsn = "root@unix(/var/run/mysqld/mysqld.sock)/fpki"
	conn, err := mysql.Connect(config)
	panicIfError(err)

	root, err := conn.LoadRoot(ctx)
	panicIfError(err)
	fmt.Printf("root is %s\n", hex.EncodeToString((*root)[:]))

	// Ingest mock data

	// Retrieve some domains
	res, err := responder.NewMapResponder(ctx, "./config/mapserver_config.json", conn)
	panicIfError(err)
	p, err := res.GetProof(ctx, "aname.com")
	panicIfError(err)
	_ = p

	// Compare results
	return 0
}

func panicIfError(err error) {
	if err != nil {
		panic(err)
	}
}
