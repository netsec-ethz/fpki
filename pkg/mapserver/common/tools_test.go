package common

import (
	"bytes"
	"testing"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAddCert: test AddCert()
// update with new cert -> AddCert() should return true
// update with old cert -> AddCert() should return false
// then check if all the certs are correctly added
func TestAddCert(t *testing.T) {
	cert1, err := common.CTX509CertFromFile("./testdata/cert1.cer")
	require.NoError(t, err)

	cert2, err := common.CTX509CertFromFile("./testdata/cert2.cer")
	require.NoError(t, err)

	domainEntry := &DomainEntry{}

	isUpdated := domainEntry.AddCert(cert1)
	assert.True(t, isUpdated)

	isUpdated = domainEntry.AddCert(cert1)
	assert.False(t, isUpdated)

	isUpdated = domainEntry.AddCert(cert2)
	assert.True(t, isUpdated)

	isUpdated = domainEntry.AddCert(cert2)
	assert.False(t, isUpdated)

	assert.Equal(t, 2, len(domainEntry.CAEntry))

	isFound := false
	for _, caEntry := range domainEntry.CAEntry {
		if caEntry.CAName == cert1.Issuer.CommonName {
			assert.True(t, bytes.Equal(caEntry.DomainCerts[0], cert1.Raw))
			isFound = true
		}
	}
	assert.True(t, isFound)

	isFound = false
	for _, caEntry := range domainEntry.CAEntry {
		if caEntry.CAName == cert2.Issuer.CommonName {
			assert.True(t, bytes.Equal(caEntry.DomainCerts[0], cert2.Raw))
			isFound = true
		}
	}
	assert.True(t, isFound)
}

// TestAddPC: test AddPC
// update with new PC -> AddPC() should return true
// update with old PC -> AddPC() should return false
// then check if all the PC are correctly added
func TestAddPC(t *testing.T) {
	pc1 := common.PC{
		CAName:  "ca1",
		Subject: "before",
	}

	pc2 := common.PC{
		CAName:  "ca1",
		Subject: "after",
	}

	pc3 := common.PC{
		CAName:  "ca2",
		Subject: "after",
	}

	domainEntry := &DomainEntry{}

	isUpdated := domainEntry.AddPC(&pc1)
	assert.True(t, isUpdated)

	isUpdated = domainEntry.AddPC(&pc3)
	assert.True(t, isUpdated)

	isUpdated = domainEntry.AddPC(&pc1)
	assert.False(t, isUpdated)

	isUpdated = domainEntry.AddPC(&pc3)
	assert.False(t, isUpdated)

	for _, caList := range domainEntry.CAEntry {
		if caList.CAName == "ca1" {
			assert.True(t, caList.CurrentPC.Subject == "before")
		}
	}

	isUpdated = domainEntry.AddPC(&pc2)
	assert.True(t, isUpdated)

	for _, caList := range domainEntry.CAEntry {
		if caList.CAName == "ca1" {
			assert.True(t, caList.CurrentPC.Subject == "after")
		}
	}
}

// TestAddRPC: test AddRPC
// update with new RPC -> AddRPC() should return true
// update with old RPC -> AddRPC() should return false
// then check if all the RPC are correctly added
func TestAddRPC(t *testing.T) {
	rpc1 := common.RPC{
		CAName:  "ca1",
		Subject: "before",
	}

	rpc2 := common.RPC{
		CAName:  "ca1",
		Subject: "after",
	}

	rpc3 := common.RPC{
		CAName:  "ca2",
		Subject: "after",
	}

	domainEntry := &DomainEntry{}

	isUpdated := domainEntry.AddRPC(&rpc1)
	assert.True(t, isUpdated)

	isUpdated = domainEntry.AddRPC(&rpc3)
	assert.True(t, isUpdated)

	isUpdated = domainEntry.AddRPC(&rpc1)
	assert.False(t, isUpdated)

	isUpdated = domainEntry.AddRPC(&rpc3)
	assert.False(t, isUpdated)

	for _, caList := range domainEntry.CAEntry {
		if caList.CAName == "ca1" {
			assert.True(t, caList.CurrentRPC.Subject == "before")
		}
	}

	isUpdated = domainEntry.AddRPC(&rpc2)
	assert.True(t, isUpdated)

	for _, caList := range domainEntry.CAEntry {
		if caList.CAName == "ca1" {
			assert.True(t, caList.CurrentRPC.Subject == "after")
		}
	}
}
