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

	const baseCTSize = 2 * 1000 * 1000
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

	responder, err := responder.NewMapResponder(ctx, root, 233, 10)
	if err != nil {
		panic(err)
	}

	numOfWorker := 20

	step := len(collectedCerts) / numOfWorker
	fetchStartTime := time.Now()

	wg.Add(numOfWorker)
	for i := 0; i < numOfWorker; i++ {
		go collectProof(responder, collectedCerts[i*step:i*step+step-1])
	}
	wg.Wait()

	fetchEndTime := time.Now()
	fmt.Println("time to fetch proofs: ", fetchEndTime.Sub(fetchStartTime))
}

func collectProof(responder *responder.MapResponder, certs []*ctX509.Certificate) {
	defer wg.Done()
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	numOfQuery := 0
	for _, cert := range certs {
		if cert.Subject.CommonName != "" {
			_, err := responder.GetProof(ctx, cert.Subject.CommonName)
			if err != nil && err != domain.InvalidDomainNameErr {
				panic(err)
			}
		}
		numOfQuery++
		//fmt.Println(numOfQuery, " / ", len(certs))
	}
	fmt.Println("finished !", numOfQuery)
}
