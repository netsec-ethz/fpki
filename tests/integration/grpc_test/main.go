package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/netsec-ethz/fpki/pkg/domain"
	"github.com/netsec-ethz/fpki/pkg/grpc/grpcclient"
	"github.com/netsec-ethz/fpki/pkg/grpc/grpcserver"
	"github.com/netsec-ethz/fpki/pkg/mapserver/prover"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	dbtest "github.com/netsec-ethz/fpki/tests/pkg/db"

	ct "github.com/google/certificate-transparency-go"
	ctTls "github.com/google/certificate-transparency-go/tls"
	ctX509 "github.com/google/certificate-transparency-go/x509"
	mapCommon "github.com/netsec-ethz/fpki/pkg/mapserver/common"
)

var wg sync.WaitGroup

func main() {
	dbtest.TruncateAllTablesWithoutTestObject()

	// new map updator
	mapUpdater, err := updater.NewMapUpdater(nil, 233)
	if err != nil {
		panic(err)
	}

	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	mapUpdater.Fetcher.BatchSize = 10000
	mapUpdater.StartFetching("https://ct.googleapis.com/logs/argon2021", 1120000, 1120999)
	_, err = mapUpdater.UpdateNextBatch(ctx)
	if err != nil {
		panic(err)
	}

	err = mapUpdater.CommitSMTChanges(ctx)
	if err != nil {
		panic(err)
	}

	root := mapUpdater.GetRoot()
	err = mapUpdater.Close()
	if err != nil {
		panic(err)
	}

	// get a new responder, and load an existing tree
	mapResponder, err := grpcserver.NewGRPCServer(ctx, root, 233, "./config/mapserver_config.json")
	if err != nil {
		panic(err)
	}

	closeChan := make(chan byte)
	go mapResponder.StartWork(closeChan, 50051)

	// re-collect the added certs
	collectedCertMap := []ctX509.Certificate{}
	for i := 0; i < 50; i++ {
		certList, err := getCerts("https://ct.googleapis.com/logs/argon2021", int64(1120000+i*20), int64(1120000+i*20+19))
		//fmt.Println("downloading : ", int64(1120000+i*20), " - ", int64(1120000+i*20+19))
		if err != nil {
			panic(err)
		}
		collectedCertMap = append(collectedCertMap, certList...)
	}

	numberOfWorker := 15
	wg.Add(numberOfWorker)
	step := len(collectedCertMap) / numberOfWorker

	for i := 0; i < numberOfWorker; i++ {
		worker(ctx, collectedCertMap[i*step:i*step+step-1])
	}

	wg.Wait()

	closeChan <- 1

	fmt.Println("map server succeed!")
}

func worker(ctx context.Context, certs []ctX509.Certificate) {
	for _, cert := range certs {
		if cert.Subject.CommonName != "" {
			proofs, err := grpcclient.GetProofs(cert.Subject.CommonName, 50051)
			if err != nil {
				if err == domain.ErrInvalidDomainName {
					continue
				}
				panic(err)
			}
			if !checkProof(cert, proofs) {
				panic("certs not found")
			}
		}
	}
	wg.Done()
}

func checkProof(cert ctX509.Certificate, proofs []mapCommon.MapServerResponse) bool {
	caName := cert.Issuer.String()
	for _, proof := range proofs {
		if !strings.Contains(cert.Subject.CommonName, proof.Domain) {
			panic("wrong domain proofs")
		}
		proofType, isCorrect, err := prover.VerifyProofByDomain(proof)
		if err != nil {
			panic(err)
		}

		if !isCorrect {
			panic("wrong proof")
		}

		if proofType == mapCommon.PoA {
			if len(proof.DomainEntryBytes) != 0 {
				panic("domain entry bytes not empty for PoA")
			}
		}
		if proofType == mapCommon.PoP {
			domainEntry, err := mapCommon.DeserializeDomainEntry(proof.DomainEntryBytes)
			if err != nil {
				panic(err)
			}
			// get the correct CA entry
			for _, caEntry := range domainEntry.Entries {
				if caEntry.CAName == caName {
					// check if the cert is in the CA entry
					for _, certRaw := range caEntry.DomainCerts {
						if bytes.Equal(certRaw, cert.Raw) {
							return true
						}
					}
				}
			}
		}
	}
	return false
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
		var merkleLeaf ct.MerkleTreeLeaf
		ctTls.Unmarshal(leafBytes, &merkleLeaf)

		var certificate *ctX509.Certificate
		switch entryType := merkleLeaf.TimestampedEntry.EntryType; entryType {
		case ct.X509LogEntryType:
			certificate, err = ctX509.ParseCertificate(merkleLeaf.TimestampedEntry.X509Entry.Data)
			if err != nil {
				fmt.Println("ERROR: ParseCertificate ", err)
				continue parse_cert_loop
			}
		case ct.PrecertLogEntryType:
			certificate, err = ctX509.ParseTBSCertificate(merkleLeaf.TimestampedEntry.PrecertEntry.TBSCertificate)
			if err != nil {
				fmt.Println("ERROR: ParseTBSCertificate ", err)
				continue parse_cert_loop
			}
		}
		certList = append(certList, *certificate)
	}
	return certList, nil
}
