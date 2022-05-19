package logpicker

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	//"github.com/davecgh/go-spew/spew"
	ct "github.com/google/certificate-transparency-go"
	ctTls "github.com/google/certificate-transparency-go/tls"
	ctX509 "github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
)

//https://ct.googleapis.com/logs/argon2021/ct/v1/get-entries?start=%d&end=%d&quot

// CertData: data structure of leaf from CT log
type CertData struct {
	LeafInput string `json:"leaf_input"`
	ExtraData string `json:"extra_data"`
}

// CertLog: Data from CT log
type CertLog struct {
	Entries []CertData
}

// UpdateCertResult: result of the update
type UpdateCertResult struct {
	Err                error
	EffectedDomainsNum int
	NumOfFetchedCert   int
}

// get certificate from CT log
func getCerts(ctURL string, start int64, end int64) ([]*ctX509.Certificate, error) {
	url := fmt.Sprintf(ctURL+"/ct/v1/get-entries?start=%d&end=%d&quot", start, end)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("http.Get %w", err)
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)

	var resultsCerLog CertLog
	json.Unmarshal(buf.Bytes(), &resultsCerLog)

	certList := []*ctX509.Certificate{}

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
		certList = append(certList, certificate)
	}

	return certList, nil
}

// workerThread: worker thread for log picker
func workerThread(ctURL string, start, end int64, resultChan chan UpdateCertResult, processorChan chan UpdateRequest, batchSize int) {
	processorResultChan := make(chan UpdateResult)
	effectedDomainsNum := 0
	numberOfFetchedCerts := 0
	var certs []*ctX509.Certificate

	for i := start; i < end; i += 20 {
		var newCerts []*ctX509.Certificate
		var err error
		// TODO(yongzhe): better error handling; retry if error happens
		if end-i > 20 {
			newCerts, err = getCerts(ctURL, i, i+19)
			if err != nil {
				resultChan <- UpdateCertResult{Err: err, NumOfFetchedCert: numberOfFetchedCerts}
				continue
			}
		} else {
			newCerts, err = getCerts(ctURL, i, i+end-i)
			if err != nil {
				resultChan <- UpdateCertResult{Err: err, NumOfFetchedCert: numberOfFetchedCerts}
				continue
			}
		}
		certs = append(certs, newCerts...)

		// if batch size is reached, or if this is the last round
		if len(certs) > batchSize || i+20 > end {
			// to generate unique list
			uniqEffectedDomains := make(map[string]byte)

			// map for store [certificate]-[effected domain] pair
			certDomainMap := make(map[*ctX509.Certificate][]string)

			// parse certificate, get effected domains
			for _, cert := range certs {
				// to get unique slice
				domainNameMap := make(map[string]byte)
				for _, domainName := range cert.DNSNames {
					domainNameMap[domainName] = 1
				}
				if len(cert.Subject.CommonName) != 0 {
					domainNameMap[cert.Subject.CommonName] = 1
				}

				// to get unique slice
				domainNames := []string{}
				for k := range domainNameMap {
					domainNames = append(domainNames, k)
				}

				// effected domains of this certificate
				var effectedDomains []string
				switch {
				case len(domainNames) >= 1:
					effectedDomains = ExtractEffectedDomains(domainNames)
				case len(domainNames) == 0:
					continue
				}

				// add effected domain to the map
				for _, v := range effectedDomains {
					uniqEffectedDomains[v] = 1
				}

				// store [certificate]-[effected domain] pair
				certDomainMap[cert] = effectedDomains
				effectedDomainsNum = effectedDomainsNum + len(effectedDomains)
			}

			// if no domain is effected, go to next query
			if len(uniqEffectedDomains) == 0 {
				continue
			}

			// get the hashes of names of effected Domains
			requestDomainsHash := [][32]byte{}
			for domainName := range uniqEffectedDomains {
				domainHash := trie.Hasher([]byte(domainName))
				var domainHash32bytes [32]byte
				copy(domainHash32bytes[:], domainHash)
				requestDomainsHash = append(requestDomainsHash, domainHash32bytes)
			}

			// send request to db work distributer
			updateRequest := UpdateRequest{RequestType: QueryDomain,
				Domains:    requestDomainsHash,
				ReturnChan: processorResultChan}

			retryNum := 0
			var queryResult UpdateResult
			for {
				// send request
				processorChan <- updateRequest
				queryResult = <-processorResultChan

				if queryResult.Err == nil {
					break
					// resource not avaliable; other thread is updating (part of) the requested resource
				} else if queryResult.Err == ErrorResourceLocked {
					// TODO(yongzhe): Ugly approach
					retryNum++
					// sleep random time
					time.Sleep(time.Duration(getRandomInt()) * time.Millisecond)
				}
			}

			// update the retrieved domains
			// NOTE: now the requested domains are locked. i.e. only this thread can modify the requested ranges
			// MySQL does not have a lock on non-existing rows. So we have to solve the issue in the go side.
			updatedDomainNames, updatedDomainContent, err := updateDomains(certDomainMap,
				queryResult.FetchedDomainsName, queryResult.FetchedDomainsContent)
			if err != nil {
				resultChan <- UpdateCertResult{Err: err, NumOfFetchedCert: numberOfFetchedCerts}
				return
			}

			// send updated domains to the db worker
			processorChan <- UpdateRequest{
				RequestType:          UpdateDomain,
				Domains:              requestDomainsHash,
				ReturnChan:           processorResultChan,
				UpdatedDomainName:    updatedDomainNames,
				UpdatedDomainContent: updatedDomainContent,
			}

			queryResult = <-processorResultChan

			if queryResult.Err != nil {
				resultChan <- UpdateCertResult{Err: queryResult.Err, NumOfFetchedCert: numberOfFetchedCerts}
				return
			}

			numberOfFetchedCerts = numberOfFetchedCerts + len(certs)
			certs = []*ctX509.Certificate{}
			//ln(end-start, " ", i-start)
		}
	}
	resultChan <- UpdateCertResult{EffectedDomainsNum: effectedDomainsNum, NumOfFetchedCert: numberOfFetchedCerts}
}

// update domain entries
func updateDomains(certDomainMap map[*ctX509.Certificate][]string, domainNames [][32]byte, domainContents [][]byte) ([]string, []string, error) {
	// domain entries in memory
	domainEntriesMap := make(map[[32]byte]*common.DomainEntry)
	updatedDomainHash := make(map[[32]byte]byte)

	// parse the bytes from db to domain entries
	for i, domainHash := range domainNames {
		domainEntry, err := common.DesrialiseDomainEnrty(domainContents[i])
		if err != nil {
			return nil, nil, fmt.Errorf("updateDomains | DesrialiseDomainEnrty | %w", err)
		}
		domainEntriesMap[domainHash] = domainEntry
	}

	// update each certificate; add certificate into the effected domain
	for cert, domainList := range certDomainMap {
		for _, domainName := range domainList {
			var domainBytesCopy [32]byte
			copy(domainBytesCopy[:], trie.Hasher([]byte(domainName)))
			domainEntry, ok := domainEntriesMap[domainBytesCopy]
			// is domain entry exists in the db
			if ok {
				isUpdated := updateDomainEntry(domainEntry, cert)
				if isUpdated {
					updatedDomainHash[domainBytesCopy] = 1
				}
			} else {
				// create an empty domain entry
				newDomainEntry := &common.DomainEntry{DomainName: domainName}
				domainEntriesMap[domainBytesCopy] = newDomainEntry
				isUpdated := updateDomainEntry(newDomainEntry, cert)
				if isUpdated {
					updatedDomainHash[domainBytesCopy] = 1
				}
			}
		}
	}

	domainNameResult := []string{}
	domainContentResult := []string{}

	// marshall domain name and content
	for k, v := range domainEntriesMap {
		// only contains the updated domains
		_, ok := updatedDomainHash[k]
		if ok {
			// encode key
			encodedDomainName := hex.EncodeToString(k[:])
			domainNameResult = append(domainNameResult, encodedDomainName)

			// serialise domain entry
			domainEntryBytes, err := common.SerialiseDomainEnrty(v)
			if err != nil {
				return nil, nil, fmt.Errorf("updateDomains | SerialiseDomainEnrty | %w", err)
			}

			domainContentString := string(domainEntryBytes)
			domainContentResult = append(domainContentResult, domainContentString)
		}
	}

	return domainNameResult, domainContentResult, nil
}

// insert certificate into coresponding CAEntry
func updateDomainEntry(domainEntry *common.DomainEntry, cert *ctX509.Certificate) bool {
	caName := cert.Issuer.CommonName
	isFound := false
	isUpdated := false

ca_entry_loop:
	// iterate CAEntry list, find if the target CA list exists
	for i, _ := range domainEntry.CAEntry {
		if domainEntry.CAEntry[i].CAName == caName {
			isFound = true
			// check whether this certificate is already registered
			for _, certRaw := range domainEntry.CAEntry[i].DomainCerts {
				if bytes.Equal(certRaw, cert.Raw) {
					break ca_entry_loop
				}
			}
			// if not, append the raw of the certificate
			domainEntry.CAEntry[i].DomainCerts = append(domainEntry.CAEntry[i].DomainCerts, cert.Raw)
			isUpdated = true
			break
		}
	}

	if !isFound {
		domainEntry.CAEntry = append(domainEntry.CAEntry, common.CAEntry{DomainCerts: [][]byte{cert.Raw}, CAName: caName})
		isUpdated = true
	}
	return isUpdated
}

func getRandomInt() int {
	return rand.Intn(50)
}
