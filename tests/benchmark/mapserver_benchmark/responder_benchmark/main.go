package main

import (
	"compress/gzip"
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"math/rand"
	"os"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/domain"
	"github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/responder"
)

func main() {
	ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancelF()

	// 10M queries with 1K workers use ~ 20.3 seconds
	const totalQueries = 10 * 1000 * 1000
	const numOfWorkers = 1000
	names := getNames() // only use the first 100K names, as the updater benchmark
	_ = 0               // is limited to 100K certificates
	fmt.Printf("%d names available\n", len(names))

	fmt.Println("Loading responder ...")
	// only use one responder
	root, err := os.ReadFile("root")
	if err != nil {
		panic(err)
	}
	responder, err := responder.NewMapResponder(ctx, root, 233, 10)
	if err != nil {
		panic(err)
	}
	fmt.Printf("requesting now (%d each worker, %d workers) ...\n",
		totalQueries/numOfWorkers, numOfWorkers)
	responderStartTime := time.Now()

	proofTypes := make([]map[common.ProofType]int, numOfWorkers)
	var wg sync.WaitGroup
	for w := 0; w < numOfWorkers; w++ {
		w := w
		wg.Add(1)
		go func(queryCount int) {
			defer wg.Done()
			proofTypes[w] = make(map[common.ProofType]int)
			for i := 0; i < queryCount; i++ {
				name := names[rand.Intn(len(names))]
				proofs, err := responder.GetProof(ctx, name)
				if err != nil && err != domain.ErrInvalidDomainName {
					panic(err)
				}
				for _, p := range proofs {
					proofTypes[w][p.PoI.ProofType]++
				}
			}
		}(totalQueries / numOfWorkers)
	}
	wg.Wait()

	var presences, absences int
	for _, types := range proofTypes {
		presences += types[common.PoP]
		absences += types[common.PoA]
	}
	fmt.Printf("Presences: %d Absences: %d\n", presences, absences)
	responderDuration := time.Since(responderStartTime)

	fmt.Printf("time to fetch %d proofs: %s. 100K ~= %s\n", totalQueries,
		responderDuration, responderDuration*time.Duration(100000)/time.Duration(totalQueries))
}

func getNames() []string {
	f, err := os.Open("tests/benchmark/mapserver_benchmark/testdata/certs.pem.gz")
	if err != nil {
		panic(err)
	}
	z, err := gzip.NewReader(f)
	if err != nil {
		panic(err)
	}
	raw, err := io.ReadAll(z)
	if err != nil {
		panic(err)
	}

	certs := make([]*ctx509.Certificate, 0)
	for len(raw) > 0 {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := ctx509.ParseTBSCertificate(block.Bytes)
		if err != nil {
			panic(err)
		}
		certs = append(certs, c)
	}
	err = f.Close()
	if err != nil {
		panic(err)
	}

	names := make([]string, len(certs))
	for i, cert := range certs {
		names[i] = cert.Subject.CommonName
	}
	return names
}
