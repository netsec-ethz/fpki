package common

import (
	"crypto/rand"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//TestSerialisingDomainEntry: Serialising and deserialising of DomainEntry
func TestSerialisingDomainEntry(t *testing.T) {
	cert, err := common.X509CertFromFile("./testdata/cert.pem")
	require.NoError(t, err, "X509CertFromFile error")

	caEntry := CAEntry{
		CAName: "testCA",
		CurrentRPC: common.RPC{
			PublicKey:          []byte{1, 4, 7, 3, 2},
			PublicKeyAlgorithm: common.RSA,
			Version:            1,
		},
		Revocation:  [][]byte{generateRandomBytes()},
		DomainCerts: [][]byte{cert.Raw},
	}

	testDomainEntry := &DomainEntry{
		DomainName: "test.com",
		CAEntry:    []CAEntry{caEntry, caEntry, caEntry, caEntry, caEntry, caEntry},
	}

	start := time.Now()
	domainBytes, err := SerialiseDomainEnrty(testDomainEntry)
	require.NoError(t, err, "SerialiseDomainEnrty error")
	end := time.Now()
	fmt.Println(end.Sub(start))

	start = time.Now()
	testDomainEntryDeserialised, err := DesrialiseDomainEnrty(domainBytes)
	require.NoError(t, err, "DesrialiseDomainEnrty error")
	end = time.Now()
	fmt.Println(end.Sub(start))

	assert.Equal(t, reflect.DeepEqual(testDomainEntry, testDomainEntryDeserialised), true, "structure not equal")
}

func generateRandomBytes() []byte {
	token := make([]byte, 40)
	rand.Read(token)
	return token
}

func generateRandomBytesArray() [][]byte {
	return [][]byte{generateRandomBytes()}
}
