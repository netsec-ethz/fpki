package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"database/sql"

	ct "github.com/google/certificate-transparency-go"
	ctTls "github.com/google/certificate-transparency-go/tls"
	ctX509 "github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/mapserver/logpicker"

	_ "github.com/go-sql-driver/mysql"
	"github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
)

func main() {
	startIdx := 1100000
	endIdx := 1109999

	db, err := sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/map?maxAllowedPacket=1073741824")
	defer db.Close()
	if err != nil {
		panic(err)
	}

	// trancate domain entries table
	_, err = db.Exec("TRUNCATE `map`.`domainEntries`;")
	if err != nil {
		panic(err)
	}

	logPicker, err := logpicker.NewLogPicker(20)
	if err != nil {
		panic(err)
	}

	// insert certificates
	start := time.Now()
	numOfAffectedDomains, numOfUpdatedCerts, err := logPicker.UpdateDomainFromLog("https://ct.googleapis.com/logs/argon2021", int64(startIdx), int64(endIdx), 70, 600)
	if err != nil {
		panic(err)
	}
	end := time.Now()
	fmt.Println("time to update 10000 certificates ", end.Sub(start))
	fmt.Println("number of affected domains: ", numOfAffectedDomains)
	fmt.Println("number of updated certs: ", numOfUpdatedCerts)

	var number int
	err = db.QueryRow("SELECT COUNT(*) FROM map.updatedDomains;").Scan(&number)
	if err != nil {
		panic(err)
	}

	fmt.Println("number of updated domains ", number)

	// trancate update index
	_, err = db.Exec("TRUNCATE `map`.`updatedDomains`;")
	if err != nil {
		panic(err)
	}

	// insert same certs again
	_, _, err = logPicker.UpdateDomainFromLog("https://ct.googleapis.com/logs/argon2021", int64(startIdx), int64(endIdx), 20, 600)

	// query the update table
	err = db.QueryRow("SELECT COUNT(*) FROM map.updatedDomains;").Scan(&number)
	if err != nil {
		panic(err)
	}

	// entries should be zero, because there is no updates
	if number != 0 {
		panic("number of new updates should be 0")
	}

	err = db.QueryRow("SELECT COUNT(*) FROM map.domainEntries;").Scan(&number)
	if err != nil {
		panic(err)
	}

	fmt.Println("number of entries in db: ", number)

	// re-collect the certs, to see whether they are in the place where they should be
	collectedCertMap := []ctX509.Certificate{}
	for i := 0; i < 50; i++ {
		certList, err := getCerts("https://ct.googleapis.com/logs/argon2021", int64(startIdx+i*20), int64(startIdx+i*20+19))
		fmt.Println("doanloading : ", int64(startIdx+i*20), " - ", int64(startIdx+i*20+19))
		if err != nil {
			panic(err)
		}
		for _, cert := range certList {
			collectedCertMap = append(collectedCertMap, cert)
		}
	}

	for _, cert := range collectedCertMap {
		uniqDomainNameList := make(map[string]byte)
		if len(cert.Subject.CommonName) != 0 {
			uniqDomainNameList[cert.Subject.CommonName] = 1
		}
		if len(cert.DNSNames) != 0 {
			for _, name := range cert.DNSNames {
				uniqDomainNameList[name] = 1
			}
		}

		domainList := []string{}
		for name := range uniqDomainNameList {
			domainList = append(domainList, name)
		}

		effectedDomainName := logpicker.ExtractEffectedDomains(domainList)
		for _, domainName := range effectedDomainName {
			err := checkDomainEntryIsCorrectlySet(db, domainName, cert)
			if err != nil {
				panic(err)
			}
		}
	}

	fmt.Println("test passed")
}

// check domain one by one
func checkDomainEntryIsCorrectlySet(dbConn *sql.DB, domainName string, cert ctX509.Certificate) error {
	domainHash := trie.Hasher([]byte(domainName))
	key := hex.EncodeToString(domainHash[:])

	var domainContent string
	err := dbConn.QueryRow("SELECT `value`  from `map`.`domainEntries` WHERE `key` IN ('" + key + "');").Scan(&domainContent)
	if err != nil {
		return fmt.Errorf("checkDomainEntryIsCorrectlySet | QueryRow | %w", err)
	}

	domainEntries, err := common.DesrialiseDomainEnrty([]byte(domainContent))
	if err != nil {
		return fmt.Errorf("checkDomainEntryIsCorrectlySet | DesrialiseDomainEnrty | %w", err)
	}

	if domainEntries.DomainName != domainName {
		return fmt.Errorf("checkDomainEntryIsCorrectlySet | domain name not correctly set.")
	}

	caName := cert.Issuer.CommonName
	for _, caEntry := range domainEntries.CAEntry {
		if caEntry.CAName == caName {
			for _, certRaw := range caEntry.DomainCerts {
				if bytes.Equal(certRaw, cert.Raw) {
					return nil
				}
			}
		}
	}

	return fmt.Errorf("certificate not found")
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
