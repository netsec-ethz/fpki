package responder

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDomainName(t *testing.T) {
	result, err := parseDomainName("www.baidu.com")
	require.NoError(t, err, "parseDomainName error")
	assert.Equal(t, 1, len(result), "length error")
}
