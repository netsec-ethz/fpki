package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/gob"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/domain"
	"github.com/netsec-ethz/fpki/pkg/mapserver/logpicker"
)

type uniqueStringSet map[string]struct{}

func main() {
	content, err := ioutil.ReadFile("domainCount")

	var readMap map[string]int
	bytes := bytes.NewBuffer(content)

	d := gob.NewDecoder(bytes)

	// Decoding the serialized data
	err = d.Decode(&readMap)
	if err != nil {
		panic(err)
	}

	fmt.Println(readMap["dotcms-tridv.hcahealthcare.com"])
	const baseCTSize = 2*1000 + 1600000
	const count = 500 * 1000

	fetcher := logpicker.LogFetcher{
		URL:         "https://ct.googleapis.com/logs/argon2021",
		Start:       baseCTSize,
		End:         baseCTSize + count,
		WorkerCount: 16,
	}

	fetcher.StartFetching()

	testSet6 := make(map[string]byte)
	testSet10 := make(map[string]byte)
	testSet20 := make(map[string]byte)
	testSet50 := make(map[string]byte)
	testSet100 := make(map[string]byte)
	testSet200 := make(map[string]byte)
	testSet500 := make(map[string]byte)
	testSet1000 := make(map[string]byte)

	getCerts := 0

	ctx, cancelF := context.WithTimeout(context.Background(), 200*time.Minute)
	defer cancelF()

	certNum := 0

	for certNum < 500*1000 {
		certs, err := fetcher.NextBatch(ctx)
		certNum = certNum + len(certs)
		if err != nil {
			panic(err)
		}
		getCerts = getCerts + len(certs)

		for _, cert := range certs {

			if len(cert.Subject.CommonName) == 0 {
				continue
			}

			domainNames, err := domain.ParseDomainName(cert.Subject.CommonName)
			if err != nil {
				continue
			}

			totalNum := 0
			for _, name := range domainNames {
				totalNum = totalNum + readMap[name]
			}

			if totalNum < 5 {
				testSet6[cert.Subject.CommonName] = 1
			} else if totalNum < 10 {
				testSet10[cert.Subject.CommonName] = 1
			} else if totalNum < 20 {
				testSet20[cert.Subject.CommonName] = 1
			} else if totalNum < 50 {
				testSet50[cert.Subject.CommonName] = 1
			} else if totalNum < 100 {
				testSet100[cert.Subject.CommonName] = 1
			} else if totalNum < 200 {
				testSet200[cert.Subject.CommonName] = 1
			} else if totalNum < 500 {
				testSet500[cert.Subject.CommonName] = 1
			} else if totalNum < 1000 {
				testSet1000[cert.Subject.CommonName] = 1
			}
		}

		fmt.Println("--------------------------------------")
		fmt.Println("*", len(testSet6))
		fmt.Println("*", len(testSet10))
		fmt.Println("*", len(testSet20))
		fmt.Println("*", len(testSet50))
		fmt.Println("*", len(testSet100))
		fmt.Println("*", len(testSet200))
		fmt.Println("*", len(testSet500))
		fmt.Println("*", len(testSet1000))
	}

	fmt.Println(getCerts)
	fmt.Println("done")

	for name := range testSet6 {
		domainNames, err := domain.ParseDomainName(name)
		if err != nil {
			continue
		}

		for _, n := range domainNames {
			if readMap[n] > 4 {
				panic("length error")
			}
		}
	}

	outputFile, err := os.OpenFile("testData6.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}

	datawriter := bufio.NewWriter(outputFile)

	for domainName := range testSet6 {
		_, _ = datawriter.WriteString(domainName + "\n")
	}

	datawriter.Flush()
	outputFile.Close()

	outputFile, err = os.OpenFile("testData10.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}

	datawriter = bufio.NewWriter(outputFile)

	for domainName := range testSet10 {
		_, _ = datawriter.WriteString(domainName + "\n")
	}

	datawriter.Flush()
	outputFile.Close()

	outputFile, err = os.OpenFile("testData20.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}

	datawriter = bufio.NewWriter(outputFile)

	for domainName := range testSet20 {
		_, _ = datawriter.WriteString(domainName + "\n")
	}

	datawriter.Flush()
	outputFile.Close()

	outputFile, err = os.OpenFile("testData50.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}

	datawriter = bufio.NewWriter(outputFile)

	for domainName := range testSet50 {
		_, _ = datawriter.WriteString(domainName + "\n")
	}

	datawriter.Flush()
	outputFile.Close()

	outputFile, err = os.OpenFile("testData100.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}

	datawriter = bufio.NewWriter(outputFile)

	for domainName := range testSet100 {
		_, _ = datawriter.WriteString(domainName + "\n")
	}

	datawriter.Flush()
	outputFile.Close()

	outputFile, err = os.OpenFile("testData200.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}

	datawriter = bufio.NewWriter(outputFile)

	for domainName := range testSet200 {
		_, _ = datawriter.WriteString(domainName + "\n")
	}

	datawriter.Flush()
	outputFile.Close()

	outputFile, err = os.OpenFile("testData500.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}

	datawriter = bufio.NewWriter(outputFile)

	for domainName := range testSet500 {
		_, _ = datawriter.WriteString(domainName + "\n")
	}

	datawriter.Flush()
	outputFile.Close()

	outputFile, err = os.OpenFile("testData1000.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}

	datawriter = bufio.NewWriter(outputFile)

	for domainName := range testSet1000 {
		_, _ = datawriter.WriteString(domainName + "\n")
	}

	datawriter.Flush()
	outputFile.Close()

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
