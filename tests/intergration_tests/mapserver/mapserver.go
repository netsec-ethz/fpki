package main

import (
	"database/sql"
	"fmt"
	"math/rand"

	"github.com/netsec-ethz/fpki/pkg/common"
	mapCommon "github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/responder"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"

	"time"

	prover "github.com/netsec-ethz/fpki/pkg/mapserver/prover"
)

// TestUpdaterAndResponder: store a list of domain entries -> fetch inclusion -> verify inclusion
func main() {
	db, err := sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/map?maxAllowedPacket=1073741824")
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
	err = mapUpdater.UpdateDomains(testDomain)
	if err != nil {
		panic(err)
	}

	end := time.Now()
	fmt.Println("time to update 10000 domain entries: ", end.Sub(start))

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
	err = mapResponder.ReadDomainEntriesFromDB(testDomain)
	if err != nil {
		panic(err)
	}

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
	}
	fmt.Println("map server succeed!")
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
