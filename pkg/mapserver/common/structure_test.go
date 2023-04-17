package common

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/util"
	"github.com/stretchr/testify/require"
)

// TestSerializingDomainEntry: Serializing and deserializing of DomainEntry
func TestSerializeDomainEntry(t *testing.T) {
	cert, err := common.X509CertFromFile("./testdata/cert.pem")
	require.NoError(t, err, "X509CertFromFile error")

	testDomainEntry := &DomainEntry{
		DomainName: "test.com",
		DomainID:   common.SHA256Hash([]byte("test.com")),
		RPCs: []common.RPC{
			{
				PublicKey:          []byte{1, 4, 7, 3, 2},
				PublicKeyAlgorithm: common.RSA,
				Version:            1,
			},
			{
				PublicKey:          []byte{2, 4, 7, 3, 2},
				PublicKeyAlgorithm: common.RSA,
				Version:            2,
			},
		},
		PCs: []common.SP{
			{
				Policies: common.Policy{
					TrustedCA:         []string{"ca1", "ca2"},
					AllowedSubdomains: []string{"flowers.com"},
				},
				// TimeStamp:    time.Now(),
				TimeStamp:    util.TimeFromSecs(42),
				SerialNumber: 1,
				SPTs: []common.SPT{
					{
						Version:         1,
						Subject:         "spt subject",
						STH:             []byte{0, 1, 2, 3},
						STHSerialNumber: 12345,
						PoI:             []byte{0, 1, 2, 3, 4, 5, 6, 7},
					},
				},
			},
		},
		DomainCerts: cert.Raw,
	}

	domainBytes, err := SerializeDomainEntry(testDomainEntry)
	require.NoError(t, err, "SerializedDomainEntry error")

	fmt.Println(string(domainBytes))
	testDomainEntryDeserialized, err := DeserializeDomainEntry(domainBytes)
	require.NoError(t, err, "DeserializeDomainEntry error")

	require.True(t, cmp.Equal(testDomainEntry, testDomainEntryDeserialized))
	// assert.EqualValues(t, testDomainEntry, testDomainEntryDeserialized)
	// assert.Equal(t, reflect.DeepEqual(testDomainEntry, testDomainEntryDeserialized), true, "structure not equal")
}

// TestAddCert: test AddCert()
// update with new cert -> AddCert() should return true
// update with old cert -> AddCert() should return false
// then check if all the certs are correctly added
func TestAddCert(t *testing.T) {
	// cert1, err := common.CTX509CertFromFile("./testdata/cert1.cer")
	// require.NoError(t, err)

	// cert2, err := common.CTX509CertFromFile("./testdata/cert2.cer")
	// require.NoError(t, err)

	// emptyChain := []*ctx509.Certificate{}

	// domainEntry := &DomainEntry{}

	// isUpdated := domainEntry.AddCert(cert1, emptyChain)
	// assert.True(t, isUpdated)

	// isUpdated = domainEntry.AddCert(cert1, emptyChain)
	// assert.False(t, isUpdated)

	// isUpdated = domainEntry.AddCert(cert2, emptyChain)
	// assert.True(t, isUpdated)

	// isUpdated = domainEntry.AddCert(cert2, emptyChain)
	// assert.False(t, isUpdated)

	// assert.Equal(t, 2, len(domainEntry.Entries))

	// isFound := false
	// issuerRepresentation := cert1.Issuer.String()
	// for _, caEntry := range domainEntry.Entries {
	// 	if caEntry.CAName == issuerRepresentation {
	// 		assert.True(t, bytes.Equal(caEntry.DomainCerts[0], cert1.Raw))
	// 		isFound = true
	// 	}
	// }
	// assert.True(t, isFound)

	// isFound = false
	// issuerRepresentation = cert2.Issuer.String()
	// for _, caEntry := range domainEntry.Entries {
	// 	if caEntry.CAName == issuerRepresentation {
	// 		assert.True(t, bytes.Equal(caEntry.DomainCerts[0], cert2.Raw))
	// 		isFound = true
	// 	}
	// }
	// assert.True(t, isFound)
}

// TestAddPC: test AddPC
// update with new PC -> AddPC() should return true
// update with old PC -> AddPC() should return false
// then check if all the PC are correctly added
func TestAddPC(t *testing.T) {
	// pc1 := common.SP{
	// 	CAName:  "ca1",
	// 	Subject: "before",
	// }

	// pc2 := common.SP{
	// 	CAName:  "ca1",
	// 	Subject: "after",
	// }

	// pc3 := common.SP{
	// 	CAName:  "ca2",
	// 	Subject: "after",
	// }

	// domainEntry := &DomainEntry{}

	// isUpdated := domainEntry.AddPC(&pc1)
	// assert.True(t, isUpdated)

	// isUpdated = domainEntry.AddPC(&pc3)
	// assert.True(t, isUpdated)

	// isUpdated = domainEntry.AddPC(&pc1)
	// assert.False(t, isUpdated)

	// isUpdated = domainEntry.AddPC(&pc3)
	// assert.False(t, isUpdated)

	// for _, caList := range domainEntry.Entries {
	// 	if caList.CAName == "ca1" {
	// 		assert.True(t, caList.PCs.Subject == "before")
	// 	}
	// }

	// isUpdated = domainEntry.AddPC(&pc2)
	// assert.True(t, isUpdated)

	// for _, caList := range domainEntry.Entries {
	// 	if caList.CAName == "ca1" {
	// 		assert.True(t, caList.PCs.Subject == "after")
	// 	}
	// }
}

// TestAddRPC: test AddRPC
// update with new RPC -> AddRPC() should return true
// update with old RPC -> AddRPC() should return false
// then check if all the RPC are correctly added
func TestAddRPC(t *testing.T) {
	// rpc1 := common.RPC{
	// 	CAName:  "ca1",
	// 	Subject: "before",
	// }

	// rpc2 := common.RPC{
	// 	CAName:  "ca1",
	// 	Subject: "after",
	// }

	// rpc3 := common.RPC{
	// 	CAName:  "ca2",
	// 	Subject: "after",
	// }

	// domainEntry := &DomainEntry{}

	// isUpdated := domainEntry.AddRPC(&rpc1)
	// assert.True(t, isUpdated)

	// isUpdated = domainEntry.AddRPC(&rpc3)
	// assert.True(t, isUpdated)

	// isUpdated = domainEntry.AddRPC(&rpc1)
	// assert.False(t, isUpdated)

	// isUpdated = domainEntry.AddRPC(&rpc3)
	// assert.False(t, isUpdated)

	// for _, caList := range domainEntry.Entries {
	// 	if caList.CAName == "ca1" {
	// 		assert.True(t, caList.RPCs.Subject == "before")
	// 	}
	// }

	// isUpdated = domainEntry.AddRPC(&rpc2)
	// assert.True(t, isUpdated)

	// for _, caList := range domainEntry.Entries {
	// 	if caList.CAName == "ca1" {
	// 		assert.True(t, caList.RPCs.Subject == "after")
	// 	}
	// }
}

func generateRandomBytes() []byte {
	token := make([]byte, 40)
	rand.Read(token)
	return token
}

func generateRandomBytesArray() [][]byte {
	return [][]byte{generateRandomBytes()}
}
