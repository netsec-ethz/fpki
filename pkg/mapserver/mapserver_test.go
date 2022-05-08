package mapserver

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"fmt"
	"time"
)

func Test(t *testing.T) {
	testDomain, domainMap := getRandomDomainEntry()

	mapServer, err := NewMapServer("root:@tcp(127.0.0.1:3306)/map?maxAllowedPacket=1073741824", 233)
	require.NoError(t, err, "db conn error")

	err = mapServer.UpdateDomains(testDomain)
	require.NoError(t, err, "update error")

	domains := []string{}
	for _, domain := range testDomain {
		domains = append(domains, domain.domainName)
	}

	start := time.Now()
	proofs, err := mapServer.GetProofs(domains)
	require.NoError(t, err, "GetProofs error")

	end := time.Now()
	fmt.Println(end.Sub(start))

	for _, proof := range proofs {
		proofType, isCorrect := VerifyProofByDomain(proof, domainMap[proof.domain])
		assert.Equal(t, proofType, PoP, "proof type error")
		assert.Equal(t, isCorrect, true, "proof Verification error")
	}
}

func getRandomDomainEntry() ([]DomainEntry, map[string]DomainEntry) {
	domainEntries := []DomainEntry{}
	domainMaps := make(map[string]DomainEntry)
	for i := 0; i < 10000; i++ {
		domainName := RandStringRunes(30)
		certificates := generateRandomBytesArray()
		domainEntrie := DomainEntry{domainName: domainName, certificates: certificates}
		domainEntries = append(domainEntries, domainEntrie)
		domainMaps[domainName] = domainEntrie
	}
	return domainEntries, domainMaps
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func generateRandomBytes() []byte {
	token := make([]byte, 32)
	rand.Read(token)
	return token
}

func generateRandomBytesArray() [][]byte {
	return [][]byte{generateRandomBytes()}
}

/*

import (
	"fmt"
	"math/rand"
	"testing"
)

func TestSort(t *testing.T) {
	domainEntries := []DomainEntry{}

	for i := 0; i < 100; i++ {
		domainEntries = append(domainEntries, DomainEntry{domainName: RandStringRunes(80), certificates: generateRandomBytesArray()})
	}

	result := HashDomainEntriesThenSort(domainEntries)
	for _, k := range result {
		fmt.Println(k.key)
	}
}

*/
