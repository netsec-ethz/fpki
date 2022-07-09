package main

import (
	"bytes"
	"context"
	"encoding/gob"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/mapserver/logpicker"
)

type uniqueStringSet map[string]struct{}

func main() {
	/*
		const baseCTSize = 2*1000 + 1600000
		const count = 5000 * 1000

		fetcher := logpicker.LogFetcher{
			URL:         "https://ct.googleapis.com/logs/argon2021",
			Start:       baseCTSize,
			End:         baseCTSize + count,
			WorkerCount: 16,
		}

		fetcher.StartFetching()

		ctx, cancelF := context.WithTimeout(context.Background(), 200*time.Minute)
		defer cancelF()

		getCerts := 0

		domainCount := make(map[string]int)

		for getCerts < 4000*1000 {
			start := time.Now()
			certs, err := fetcher.NextBatch(ctx)
			if err != nil {
				panic(err)
			}
			getCerts = getCerts + len(certs)
			fmt.Println(getCerts)

			for _, cert := range certs {
				domains := extractCertDomains(cert)
				if len(domains) == 0 {
					continue
				}

				// get affected domains
				affectedDomains := domain.ExtractAffectedDomains(domains)
				if len(affectedDomains) == 0 {
					continue
				}

				for _, domainName := range affectedDomains {
					if _, ok := domainCount[domainName]; !ok {
						domainCount[domainName] = 1
					} else {
						domainCount[domainName]++
					}
				}
			}
			fmt.Println()
			fmt.Println("***********************************")
			for k, v := range domainCount {
				if v > 1000 {
					fmt.Println(k, " ", v)
				}
			}
			end := time.Now()
			fmt.Println("***********************************")

			fmt.Println(end.Sub(start))

		}

		b := new(bytes.Buffer)

		e := gob.NewEncoder(b)

		// Encoding the map
		err := e.Encode(domainCount)
		if err != nil {
			panic(err)
		}

		fo, err := os.Create("domainCount")
		if err != nil {
			panic(err)
		}

		if _, err := fo.Write(b.Bytes()); err != nil {
			panic(err)
		}
	*/

	content, err := ioutil.ReadFile("domainCount")

	var readMap map[string]int
	bytes := bytes.NewBuffer(content)

	d := gob.NewDecoder(bytes)

	// Decoding the serialized data
	err = d.Decode(&readMap)
	if err != nil {
		panic(err)
	}
	const baseCTSize = 2*1000 + 1600000
	const count = 5000 * 1000

	fetcher := logpicker.LogFetcher{
		URL:         "https://ct.googleapis.com/logs/argon2021",
		Start:       baseCTSize,
		End:         baseCTSize + count,
		WorkerCount: 16,
	}

	fetcher.StartFetching()

	testSet := make(map[string]byte)

	getCerts := 0

	domainCount := make(map[string]int)

	ctx, cancelF := context.WithTimeout(context.Background(), 200*time.Minute)
	defer cancelF()

	for len(testSet) < 200*1000 {
		certs, err := fetcher.NextBatch(ctx)
		if err != nil {
			panic(err)
		}
		getCerts = getCerts + len(certs)

		for _, cert := range certs {

			if len(cert.Subject.CommonName) == 0 {
				continue
			}

			if domainCount[cert.Subject.CommonName] <= 3 {
				testSet[cert.Subject.CommonName] = 1
			}
		}

		fmt.Println(len(testSet))
	}

	fmt.Println(getCerts)
	fmt.Println("done")
	/*
		fmt.Println()
		fmt.Println("***********************************")
		for k, v := range readMap {
			if v > 20 {
				fmt.Println(k, " ", v)
			}
		}
		fmt.Println("***********************************")
	*/
}

// extractCertDomains: get domain from cert: {Common Name, SANs}
func extractCertDomains(cert *x509.Certificate) []string {
	domains := make(uniqueStringSet)
	if len(cert.Subject.CommonName) != 0 {
		domains[cert.Subject.CommonName] = struct{}{}
	}

	for _, dnsName := range cert.DNSNames {
		domains[dnsName] = struct{}{}
	}

	result := []string{}
	for k := range domains {
		result = append(result, k)
	}
	return result
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
