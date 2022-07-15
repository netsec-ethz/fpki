package main

import (
	"bytes"
	"encoding/csv"
	"encoding/gob"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/domain"
)

type uniqueStringSet map[string]struct{}

func main() {
	//countDomainDepth()
	countDomainCertsNum()
}

func countDomainCertsNum() {
	content, err := ioutil.ReadFile("domainCount")

	var readMap map[string]int
	bytes := bytes.NewBuffer(content)

	d := gob.NewDecoder(bytes)

	// Decoding the serialized data
	err = d.Decode(&readMap)
	if err != nil {
		panic(err)
	}

	fmt.Println(len(readMap))

	domainCertNum := make(map[int]int)

	for _, v := range readMap {
		if v == 1 {
			domainCertNum[1]++
		} else if v == 2 {
			domainCertNum[2]++
		} else if v == 3 {
			domainCertNum[3]++
		} else if v == 4 {
			domainCertNum[4]++
		} else if v == 5 {
			domainCertNum[5]++
		} else if v == 6 {
			domainCertNum[6]++
		} else if v == 7 {
			domainCertNum[7]++
		} else if v == 8 {
			domainCertNum[8]++
		} else if v == 9 {
			domainCertNum[9]++
		} else if v == 10 {
			domainCertNum[10]++
		} else if v <= 15 {
			domainCertNum[15]++
		} else if v <= 20 {
			domainCertNum[20]++
		} else if v <= 50 {
			domainCertNum[50]++
		} else if v <= 100 {
			domainCertNum[100]++
		} else if v <= 200 {
			domainCertNum[200]++
		} else if v <= 500 {
			domainCertNum[500]++
		} else if v <= 1000 {
			domainCertNum[1000]++
		} else if v <= 2000 {
			domainCertNum[2000]++
		} else if v <= 5000 {
			domainCertNum[5000]++
		} else if v <= 10000 {
			domainCertNum[10000]++
		}

	}

	csvFile, err := os.Create("domain_certs_num.csv")
	csvWriter := csv.NewWriter(csvFile)

	for k, v := range domainCertNum {
		csvWriter.Write([]string{strconv.Itoa(k), strconv.Itoa(v)})
		csvWriter.Flush()
	}
}

func countDomainDepth() {
	content, err := ioutil.ReadFile("domainCount")

	var readMap map[string]int
	bytes := bytes.NewBuffer(content)

	d := gob.NewDecoder(bytes)

	// Decoding the serialized data
	err = d.Decode(&readMap)
	if err != nil {
		panic(err)
	}

	levelDepthMap := make(map[int]int)
	levelDepthMap[1] = 0
	levelDepthMap[2] = 0
	levelDepthMap[3] = 0
	levelDepthMap[4] = 0
	levelDepthMap[5] = 0
	levelDepthMap[6] = 0
	levelDepthMap[7] = 0
	levelDepthMap[8] = 0
	levelDepthMap[9] = 0

	for domainName := range readMap {
		domainNames, err := domain.ParseDomainName(domainName)
		if err != nil {
			continue
		}
		levelDepthMap[len(domainNames)]++

	}

	fmt.Println(levelDepthMap)

	csvFile, err := os.Create("domain_depth.csv")
	csvWriter := csv.NewWriter(csvFile)

	for k, v := range levelDepthMap {
		csvWriter.Write([]string{strconv.Itoa(k), strconv.Itoa(v)})
		csvWriter.Flush()
	}
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
