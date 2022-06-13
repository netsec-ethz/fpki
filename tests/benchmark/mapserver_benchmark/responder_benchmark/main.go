package main

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	ctX509 "github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/domain"
	"github.com/netsec-ethz/fpki/pkg/mapserver/logpicker"
	"github.com/netsec-ethz/fpki/pkg/mapserver/responder"
)

var wg sync.WaitGroup

func main() {
	// only use one responder
	root, err := os.ReadFile("root")
	if err != nil {
		panic(err)
	}
	ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancelF()

	const baseCTSize = 2 * 1000
	const count = 10*1000 - 1 // collect 10,000 certs, for proof fetching
	fetcher := &logpicker.LogFetcher{
		URL:   "https://ct.googleapis.com/logs/argon2021",
		Start: baseCTSize,
		End:   baseCTSize + count,
	}
	collectedCerts, err := fetcher.FetchAllCertificates(ctx)
	if err != nil {
		panic(err)
	}

	names := extractNames(collectedCerts)
	responder, err := responder.NewMapResponder(ctx, root, 233, 10)
	if err != nil {
		panic(err)
	}

	numOfWorker := 20

	step := len(names) / numOfWorker
	responderStartTime := time.Now()

	wg.Add(numOfWorker)
	for i := 0; i < numOfWorker; i++ {
		go collectProof(responder, names[i*step:i*step+step-1])
	}
	wg.Wait()
	responderDuration := time.Since(responderStartTime)

	fmt.Printf("time to fetch proofs: %s. 100K ~= %s\n",
		responderDuration, responderDuration*time.Duration(100*1000/len(names)))
}

func extractNames(certs []*ctX509.Certificate) []string {
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

	numOfQuery := 0
	for _, name := range names {
		if name != "" {
			_, err := responder.GetProof(ctx, name)
			if err != nil && err != domain.InvalidDomainNameErr {
				panic(err)
			}
		}
		numOfQuery++
	}
	fmt.Println("finished !", numOfQuery)
}
