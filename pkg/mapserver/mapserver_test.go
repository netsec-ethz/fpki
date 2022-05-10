package mapserver

import (
	"database/sql"
	"fmt"
	"math/rand"
	"testing"

	"github.com/netsec-ethz/fpki/pkg/common"
	mapCommon "github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/responder"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"time"

	"github.com/cockroachdb/copyist"
	prover "github.com/netsec-ethz/fpki/pkg/mapserver/prover"
)

func init() {
	copyist.Register("postgres")
}

func TestUpdaterAndResponder(t *testing.T) {
	db, err := sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/map?maxAllowedPacket=1073741824")
	require.NoError(t, err, "updator db conn error")

	testDomain, domainMap := getRandomDomainEntry()

	mapUpdater, err := updater.NewMapUpdater(db, nil, 233)
	require.NoError(t, err, "NewMapUpdater error")

	start := time.Now()
	err = mapUpdater.UpdateDomains(testDomain)
	require.NoError(t, err, "updator update error")
	end := time.Now()
	fmt.Println("time to update 10000 domain entries: ", end.Sub(start))

	domains := []string{}
	for _, domain := range testDomain {
		domains = append(domains, domain.DomainName)
	}

	root := mapUpdater.GetRoot()
	err = mapUpdater.Close()
	require.NoError(t, err, "update close error")

	db, err = sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/map?maxAllowedPacket=1073741824")
	require.NoError(t, err, "updator db conn error")

	mapResponder, err := responder.NewMapResponder(db, root, 233)

	start = time.Now()
	proofs, err := mapResponder.GetProofs(domains)
	require.NoError(t, err, "GetProofs error")
	end = time.Now()
	fmt.Println("time to get 10000 proof: ", end.Sub(start))

	start = time.Now()
	proofs, err = mapResponder.GetProofs(domains)
	require.NoError(t, err, "GetProofs error")
	end = time.Now()
	fmt.Println("time to get 10000 proof: ", end.Sub(start))

	start = time.Now()
	for _, proof := range proofs {
		proofType, isCorrect, err := prover.VerifyProofByDomain(proof, domainMap[proof.Domain])
		assert.Equal(t, proofType, mapCommon.PoP, "inclusion proof type error")
		assert.Equal(t, isCorrect, true, "inclusion proof Verification error")
		require.NoError(t, err, "VerifyProofByDomain error")
	}
	end = time.Now()
	fmt.Println("time to verify 10000 proof: ", end.Sub(start))

	domains = []string{"no member", "hi", "this is a test"}
	proofs, err = mapResponder.GetProofs(domains)
	require.NoError(t, err, "GetProofs error")

	for _, proof := range proofs {
		proofType, isCorrect, err := prover.VerifyProofByDomain(proof, domainMap[proof.Domain])
		assert.Equal(t, proofType, mapCommon.PoA, "non-inclusion proof type error")
		assert.Equal(t, isCorrect, true, "non-inclusion proof Verification error")
		require.NoError(t, err, "VerifyProofByDomain error")
	}
}

func getRandomDomainEntry() ([]mapCommon.DomainEntry, map[string]mapCommon.DomainEntry) {
	domainEntries := []mapCommon.DomainEntry{}
	domainMaps := make(map[string]mapCommon.DomainEntry)
	for i := 0; i < 10000; i++ {
		domainName := RandStringRunes(30)
		domainEntry := mapCommon.DomainEntry{
			DomainName: domainName,
			CAEntry: []mapCommon.CAEntry{
				{
					CAName: RandStringRunes(10),
					CurrentRPC: common.RPC{
						PublicKey: generateRandomBytes(),
					},
					Revocation: generateRandomBytesArray(),
				},
			},
		}
		domainEntries = append(domainEntries, domainEntry)
		domainMaps[domainName] = domainEntry
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
