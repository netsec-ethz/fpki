package main

import (
	"compress/gzip"
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"

	ctx509 "github.com/google/certificate-transparency-go/x509"
)

// collect 1M certs, and update them
func main() {
	db.TruncateAllTablesWithoutTestObject()

	// new updater
	mapUpdater, err := updater.NewMapTestUpdater(nil, 233)
	if err != nil {
		panic(err)
	}
	ctx, cancelF := context.WithTimeout(context.Background(), 200*time.Minute)
	defer cancelF()

	var m runtime.MemStats

	for j := 0; j < 10; j++ {
		runtime.ReadMemStats(&m)
		fmt.Println("memory: ", m.Sys/1024/1024)
		fmt.Println()

		raw, err := gunzip("/home/yongxu/testdata/" + strconv.Itoa(j) + ".pem.gz")
		if err != nil {
			panic(err)
		}

		runtime.ReadMemStats(&m)
		fmt.Println("memory: ", m.Sys/1024/1024, " raw size: ", len(raw))
		fmt.Println()

		certs, err := loadCertsFromPEM(raw)
		if err != nil {
			panic(err)
		}

		raw = []byte{}

		runtime.ReadMemStats(&m)

		fmt.Println("certs length: ", len(certs), " memory: ", m.Sys/1024/1024)
		fmt.Println()

		batchSize := 10000

		for i := 0; i < len(certs)/batchSize; i++ {
			fmt.Println()
			fmt.Println()

			fmt.Println(" ---------------------- batch ", i, " ---------------------------")
			fmt.Println(" Number of certificates: ", len(certs[i*batchSize:(i+1)*batchSize-1]))
			start := time.Now()
			err = mapUpdater.UpdateCerts(ctx, certs[i*batchSize:(i+1)*batchSize-1])
			fmt.Println("time to update the changes: ", time.Since(start))

			start = time.Now()
			err = mapUpdater.CommitSMTChanges(ctx)
			if err != nil {
				panic(err)
			}
			fmt.Println("time to commit the changes: ", time.Since(start))
		}
	}

	fmt.Println("************************ Update finished ******************************")

	root := mapUpdater.GetRoot()
	err = mapUpdater.Close()
	if err != nil {
		panic(err)
	}

	err = os.WriteFile("root", root, 0644)
	if err != nil {
		panic(err)
	}
}

func loadCertsFromPEM(raw []byte) ([]*ctx509.Certificate, error) {
	certs := make([]*ctx509.Certificate, 0)
	for len(raw) > 0 {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := ctx509.ParseTBSCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	return certs, nil
}

func gunzip(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	z, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}

	raw, theErr := io.ReadAll(z)
	if theErr != nil {
		return nil, theErr
	}

	err = z.Close()
	if err != nil {
		return nil, err
	}
	err = f.Close()
	if err != nil {
		return nil, err
	}

	return raw, nil
}
