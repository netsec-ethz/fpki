package responder

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDomainName: test the parseDomainName()func
func TestDomainName(t *testing.T) {
	result, err := parseDomainName("www.baidu.com")
	require.NoError(t, err, "parseDomainName error")
	assert.Equal(t, 1, len(result), "length error")
}

func TestGetMapping(t *testing.T) {
	testDomains := []string{"a.google.com", "b.google.com", "c.google.com", "a.baidu.com"}
	domainResultMap, domainProofMap, err := getMapping(testDomains)
	require.NoError(t, err, "getMapping error")

	assert.Equal(t, 4, len(domainResultMap), "domainResultMap length error")

	proofs, ok := domainResultMap["a.google.com"]
	assert.True(t, ok, "domain not contained")
	assert.Equal(t, 2, len(proofs), "proofs length error")

	assert.Equal(t, 6, len(domainProofMap), "domainProofMap length error")
}
