package updater

import (
	"testing"

	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseDomainBytes: test ParseDomainBytes()
func TestParseDomainBytes(t *testing.T) {
	domainEntry := &common.DomainEntry{
		DomainName: "test domain",
		CAEntry: []common.CAEntry{
			{
				CAName:      "ca1",
				DomainCerts: [][]byte{{1, 2, 3}},
			},
			{
				CAName:      "ca2",
				DomainCerts: [][]byte{{2, 3, 4}},
			},
		},
	}

	serializedBytes, err := common.SerializedDomainEntry(domainEntry)
	require.NoError(t, err)

	keyValuePairs := []*db.KeyValuePair{
		{
			Key:   [32]byte{1},
			Value: serializedBytes,
		},
	}

	result, err := parseDomainBytes(keyValuePairs)
	require.NoError(t, err)

	domainEntry_, ok := result[[32]byte{1}]
	assert.True(t, ok)

	assert.Equal(t, domainEntry.DomainName, domainEntry_.DomainName)
	assert.Equal(t, domainEntry.CAEntry[0].CAName, domainEntry_.CAEntry[0].CAName)
	assert.Equal(t, domainEntry.CAEntry[1].CAName, domainEntry_.CAEntry[1].CAName)
}
