package common

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSerialisingDomainEntry(t *testing.T) {
	cert, err := common.X509CertFromFile("./testdata/cert.pem")
	require.NoError(t, err, "X509CertFromFile error")

	testDomainEntry := &DomainEntry{
		DomainName: "test.com",
		CAEntry: []CAEntry{
			{
				CAName: "testCA",
				CurrentRPC: common.RPC{
					PublicKey:          []byte{1, 4, 7, 3, 2},
					PublicKeyAlgorithm: common.RSA,
					Version:            1,
				},
				Revocation:  [][]byte{{1, 2, 5, 6, 2}},
				DomainCerts: [][]byte{cert.Raw},
			},
		},
	}

	domainBytes, err := SerialiseDomainEnrty(testDomainEntry)
	require.NoError(t, err, "SerialiseDomainEnrty error")

	testDomainEntryDeserialised, err := DesrialiseDomainEnrty(domainBytes)
	require.NoError(t, err, "DesrialiseDomainEnrty error")

	assert.Equal(t, reflect.DeepEqual(testDomainEntry, testDomainEntryDeserialised), true, "structure not equal")
	fmt.Println(testDomainEntry)
	fmt.Println(testDomainEntryDeserialised)
}
