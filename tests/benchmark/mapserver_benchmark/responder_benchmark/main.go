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
	"github.com/netsec-ethz/fpki/pkg/mapserver/responder"
)

var wg sync.WaitGroup

func main() {
	ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancelF()

	const count = 100 * 1000 // collect 10,000 names, for proof fetching
	const numOfWorkers = 200
	names := getNames()
	fmt.Printf("%d names available, using only %d\n", len(names), count)
	rand.Shuffle(len(names), func(i, j int) { names[i], names[j] = names[j], names[i] })
	names = names[:count]

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
	step := len(names) / numOfWorkers
	fmt.Printf("requesting now (%d each worker, %d workers) ...\n", step, numOfWorkers)
	responderStartTime := time.Now()

	wg.Add(numOfWorkers)
	for i := 0; i < numOfWorkers; i++ {
		go collectProof(responder, names[i*step:(i+1)*step])
	}
	wg.Wait()
	responderDuration := time.Since(responderStartTime)

	fmt.Printf("time to fetch proofs: %s. 100K ~= %s\n",
		responderDuration, responderDuration*time.Duration(100*1000/len(names)))
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

	return extractNames(certs)
}

func extractNames(certs []*ctx509.Certificate) []string {
	names := make([]string, len(certs))
	for i, cert := range certs {
		names[i] = cert.Subject.CommonName
	}
	return names
}

func collectProof(responder *responder.MapResponder, names []string) {
	defer wg.Done()
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	for _, name := range names {
		if name != "" {
			_, err := responder.GetProof(ctx, name)
			if err != nil && err != domain.InvalidDomainNameErr {
				panic(err)
			}
		}
	}
}
