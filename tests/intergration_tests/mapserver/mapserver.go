package main

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	ct "github.com/google/certificate-transparency-go"
	ctTls "github.com/google/certificate-transparency-go/tls"
	ctX509 "github.com/google/certificate-transparency-go/x509"
	mapDB "github.com/netsec-ethz/fpki/pkg/db"
	mapCommon "github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/prover"
	"github.com/netsec-ethz/fpki/pkg/mapserver/responder"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"

	"time"
)

// TestUpdaterAndResponder: store a list of domain entries -> fetch inclusion -> verify inclusion
func main() {
	// truncate tables
	db, err := sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/map?maxAllowedPacket=1073741824")
	if err != nil {
		panic(err)
	}

	_, err = db.Exec("TRUNCATE `fpki`.`deleteTest`;")
	if err != nil {
		panic(err)
	}

	_, err = db.Exec("TRUNCATE `fpki`.`domainEntries`;")
	if err != nil {
		panic(err)
	}

	_, err = db.Exec("TRUNCATE `fpki`.`updatedDomains`;")
	if err != nil {
		panic(err)
	}

	_, err = db.Exec("TRUNCATE `fpki`.`cacheStore`;")
	if err != nil {
		panic(err)
	}

	dbMap, err := mapDB.Connect_old()
	if err != nil {
		panic(err)
	}

	// new map updator
	mapUpdater, err := updater.NewMapUpdater(dbMap, nil, 233, true)
	if err != nil {
		panic(err)
	}

	start := time.Now()
	// download the certs and update the domain entries
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

	dbMap, err = mapDB.Connect_old()
	if err != nil {
		panic(err)
	}

	// get a new responder, and load an existing tree
	mapResponder, err := responder.NewMapResponder(dbMap, root, 233, true)
	if err != nil {
		panic(err)
	}

	// re-collect the added certs
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

	// check whether the certificate is correctly added to the tree
	for _, cert := range collectedCertMap {
		fmt.Println()
		fmt.Println("----------------------- new cert -------------------------")
		fmt.Println("checking cert: ", cert.Subject.CommonName, ":", cert.SerialNumber)

		// load the common name and SANs
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

		// check individual domains
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
				// if this proof is a Proof of Presence, check whether the target cert is correctly added
				if proofType == mapCommon.PoP {
					domainEntry, err := mapCommon.DesrialiseDomainEnrty(mapResponse.DomainEntryBytes)
					if err != nil {
						panic(err)
					}
					// get the correct CA entry
					for _, caEntry := range domainEntry.CAEntry {
						if caEntry.CAName == caName {
							// check if the cert is in the CA entry
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
	fmt.Println("map server succeed!")
}

// CertData: merkle tree leaf
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
