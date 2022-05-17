package main

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"

	ct "github.com/google/certificate-transparency-go"
	ctTls "github.com/google/certificate-transparency-go/tls"
	ctX509 "github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/common"
	mapCommon "github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/prover"
	"github.com/netsec-ethz/fpki/pkg/mapserver/responder"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"

	"time"
)

// TestUpdaterAndResponder: store a list of domain entries -> fetch inclusion -> verify inclusion
func main() {
	db, err := sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/map?maxAllowedPacket=1073741824")
	if err != nil {
		panic(err)
	}

	_, err = db.Exec("TRUNCATE `map`.`deleteTest`;")
	if err != nil {
		panic(err)
	}

	_, err = db.Exec("TRUNCATE `map`.`domainEntries`;")
	if err != nil {
		panic(err)
	}

	_, err = db.Exec("TRUNCATE `map`.`updatedDomains`;")
	if err != nil {
		panic(err)
	}

	_, err = db.Exec("TRUNCATE `map`.`cacheStore`;")
	if err != nil {
		panic(err)
	}

	// get random domain entries for testing
	testDomain := getRandomDomainEntry()
	domains := []string{}
	for _, domain := range testDomain {
		domains = append(domains, domain.DomainName)
	}

	// new map updator
	mapUpdater, err := updater.NewMapUpdater(db, nil, 233, true)
	if err != nil {
		panic(err)
	}

	start := time.Now()
	// update the domain entries
	err = mapUpdater.CollectCertsAndUpdate("https://ct.googleapis.com/logs/argon2021", 1000000, 1001999)
	if err != nil {
		panic(err)
	}

	end := time.Now()
	fmt.Println("time to update 2000 domain entries: ", end.Sub(start))

	root := mapUpdater.GetRoot()
	err = mapUpdater.Close()
	if err != nil {
		panic(err)
	}

	db, err = sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/map?maxAllowedPacket=1073741824")
	if err != nil {
		panic(err)
	}

	// get a new responder, and load an existing tree
	mapResponder, err := responder.NewMapResponder(db, root, 233, true)
	if err != nil {
		panic(err)
	}

	collectedCertMap := []ctX509.Certificate{}
	for i := 0; i < 100; i++ {
		certList, err := getCerts("https://ct.googleapis.com/logs/argon2021", int64(1000000+i*20), int64(1000000+i*20+19))
		fmt.Println("doanloading : ", int64(1000000+i*20), " - ", int64(1000000+i*20+19))
		if err != nil {
			panic(err)
		}
		for _, cert := range certList {
			collectedCertMap = append(collectedCertMap, cert)
		}
	}

	for _, cert := range collectedCertMap {
		fmt.Println()
		fmt.Println("----------------------- new cert -------------------------")
		fmt.Println("checking cert: ", cert.Subject.CommonName, ":", cert.SerialNumber)
		caName := cert.Issuer.CommonName
		domainNameMap := make(map[string]byte)
		if len(cert.Subject.CommonName) != 0 {
			domainNameMap[cert.Subject.CommonName] = 1
		}
		if len(cert.DNSNames) != 0 {
			for _, dnsName := range cert.DNSNames {
				domainNameMap[dnsName] = 1
			}
		}

		fmt.Println("contains domain:")
		for domainName, _ := range domainNameMap {
			fmt.Println(domainName)
		}
		fmt.Println("----------------checking-------------------")

		for domainName, _ := range domainNameMap {
			mapResponses, err := mapResponder.GetDomainProof(domainName)
			if err != nil {
				panic(err)
			}
			isContained := false
		map_response_loop:
			for _, mapResponse := range mapResponses {
				fmt.Println("---checking domain: ", mapResponse.Domain)
				proofType, isCorrect, err := prover.VerifyProofByDomain(mapResponse)
				fmt.Println("---proof type: ", proofType)
				if err != nil {
					panic(err)
				}
				if !isCorrect {
					panic("verification error")
				}
				if proofType == mapCommon.PoP {
					domainEntry, err := mapCommon.DesrialiseDomainEnrty(mapResponse.DomainEntryBytes)
					if err != nil {
						panic(err)
					}

					for _, caEntry := range domainEntry.CAEntry {
						if caEntry.CAName == caName {
							for _, certRaw := range caEntry.DomainCerts {
								if bytes.Equal(certRaw, cert.Raw) {
									isContained = true
									fmt.Println("-------------------------checked")
									break map_response_loop
								}
							}
						}
					}

				}
			}
			if isContained == false {
				panic("no valid certificate")
			}
		}
		fmt.Println()
	}

	/*
		start = time.Now()
		// get proofs for all the added domains
		proofs, err := mapResponder.GetMapResponse(domains)
		if err != nil {
			panic(err)
		}

		end = time.Now()
		fmt.Println("time to get 10000 proof: ", end.Sub(start))

		// second test, to check whether the cache is properly loaded.
		// this time, the fetching time should be much less than the previous one, because the cache is loaded
		start = time.Now()
		proofs, err = mapResponder.GetMapResponse(domains)
		if err != nil {
			panic(err)
		}

		end = time.Now()
		fmt.Println("time to get 10000 proof: ", end.Sub(start))

		start = time.Now()
		for _, proof := range proofs {
			// verify the proof
			proofType, isCorrect, err := prover.VerifyProofByDomain(proof)
			// should be Proof of Presence
			if proofType != mapCommon.PoP {
				panic("inclusion proof type error")
			}
			// verification should be correct
			if !isCorrect {
				panic("inclusion proof Verification error")
			}
			if err != nil {
				panic(err)
			}
		}
		end = time.Now()
		fmt.Println("time to verify 10000 proof: ", end.Sub(start))

		// test for non-inclusion
		domains = []string{"no member", "hi", "this is a test"}
		proofs, err = mapResponder.GetMapResponse(domains)
		if err != nil {
			panic(err)
		}

		for _, proof := range proofs {
			proofType, isCorrect, err := prover.VerifyProofByDomain(proof)
			// shoud be Proof of Absence
			if proofType != mapCommon.PoA {
				panic("non-inclusion proof type error")
			}
			// verification should be correct
			if !isCorrect {
				panic("non-inclusion proof Verification error")
			}
			if err != nil {
				panic(err)
			}
		}*/

	fmt.Println("map server succeed!")
}

type CertData struct {
	LeafInput string `json:"leaf_input"`
	ExtraData string `json:"extra_data"`
}

// CertLog: Data from CT log
type CertLog struct {
	Entries []CertData
}

// copy of function from logpicker_worker.go
func getCerts(ctURL string, start int64, end int64) ([]ctX509.Certificate, error) {
	url := fmt.Sprintf(ctURL+"/ct/v1/get-entries?start=%d&end=%d&quot", start, end)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("http.Get %w", err)
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)

	var resultsCerLog CertLog
	json.Unmarshal(buf.Bytes(), &resultsCerLog)

	certList := []ctX509.Certificate{}

	// parse merkle leaves and append it to the result
parse_cert_loop:
	for _, entry := range resultsCerLog.Entries {
		leafBytes, _ := base64.RawStdEncoding.DecodeString(entry.LeafInput)
		var merkelLeaf ct.MerkleTreeLeaf
		ctTls.Unmarshal(leafBytes, &merkelLeaf)

		var certificate *ctX509.Certificate
		switch entryType := merkelLeaf.TimestampedEntry.EntryType; entryType {
		case ct.X509LogEntryType:
			certificate, err = ctX509.ParseCertificate(merkelLeaf.TimestampedEntry.X509Entry.Data)
			if err != nil {
				fmt.Println("ERROR: ParseCertificate ", err)
				continue parse_cert_loop
			}
		case ct.PrecertLogEntryType:
			certificate, err = ctX509.ParseTBSCertificate(merkelLeaf.TimestampedEntry.PrecertEntry.TBSCertificate)
			if err != nil {
				fmt.Println("ERROR: ParseTBSCertificate ", err)
				continue parse_cert_loop
			}
		}
		certList = append(certList, *certificate)
	}

	return certList, nil
}

// get random domain entries
func getRandomDomainEntry() []mapCommon.DomainEntry {
	domainEntries := []mapCommon.DomainEntry{}
	for i := 0; i < 10000; i++ {
		domainName := randStringRunes(30)
		domainEntry := mapCommon.DomainEntry{
			DomainName: domainName,
			CAEntry: []mapCommon.CAEntry{
				{
					CAName: randStringRunes(10),
					CurrentRPC: common.RPC{
						PublicKey: generateRandomBytes(),
					},
					Revocation: generateRandomBytesArray(),
				},
			},
		}
		domainEntries = append(domainEntries, domainEntry)
	}
	return domainEntries
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

// get random strings
func randStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

// get random []byte
func generateRandomBytes() []byte {
	token := make([]byte, 32)
	rand.Read(token)
	return token
}

// get random [][]byte
func generateRandomBytesArray() [][]byte {
	return [][]byte{generateRandomBytes()}
}
