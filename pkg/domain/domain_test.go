package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIsValidDomain: test strange domain names
func TestIsValidDomain(t *testing.T) {
	parser, err := NewDomainParser()
	require.NoError(t, err)

	tests := map[string]bool{
		".com":                        false,
		"com":                         false,
		"net":                         false,
		".baidu.com":                  false,
		"423525.baidu.com":            false,
		"_www.baidu.com":              false,
		"*.*.baidu.com":               false,
		"device-a6789012.baidu.com":   true,
		"www.baidu.com":               true,
		"www.google.com":              true,
		"bqiwodnqwpdq.www.google.com": true,
	}

	for k, v := range tests {
		assert.Equal(t, v, parser.IsValidDomain(k))
	}
}

func TestUniqueValidDomainName(t *testing.T) {
	parser, err := NewDomainParser()
	require.NoError(t, err)

	assert.Equal(t, 1, len(parser.uniqueValidDomainName([]string{"www.baidu.com", "www.baidu.com"})))
	assert.Equal(t, 1, len(parser.uniqueValidDomainName([]string{"*.baidu.com", "www.baidu.com", "baidu.com"})))
	assert.Equal(t, 0, len(parser.uniqueValidDomainName([]string{"com", "*.*.baidu.com", "12378.com"})))
	assert.Equal(t, 3, len(parser.uniqueValidDomainName([]string{"video.google.com", "mail.google.com", "audio.google.com"})))
}

func TestSplitE2LD(t *testing.T) {
	result, err := SplitE2LD("baidu.com")
	assert.NoError(t, err)
	assert.Equal(t, 1, len(result))
	assert.Contains(t, result, "baidu.com")

	result, err = SplitE2LD("video.www.baidu.com")
	assert.NoError(t, err)
	assert.Equal(t, 3, len(result))
	assert.Contains(t, result, "baidu.com", "www", "video")

	result, err = SplitE2LD("video.baidu.com")
	assert.NoError(t, err)
	assert.Equal(t, 2, len(result))
	assert.Contains(t, result, "baidu.com", "video")
}

func TestFindLongestSuffix(t *testing.T) {
	input := [][]string{{"mail", "video"}, {"audio", "video"}}
	assert.Equal(t, "video.", findLongestSuffix(input))

	input = [][]string{{"tv", "mail", "video"}, {"mail", "video"}, {"mail", "video"}}
	assert.Equal(t, "mail.video.", findLongestSuffix(input))

	input = [][]string{{"tv", "mail", "mail"}, {"mail", "mail"}, {"mail", "video"}}
	assert.Equal(t, "", findLongestSuffix(input))
}

func TestExtractAffectedDomains(t *testing.T) {
	parser, err := NewDomainParser()
	require.NoError(t, err)

	result := parser.ExtractAffectedDomains([]string{"www.baidu.com", "www.google.com"})
	assert.Equal(t, 2, len(result))
	assert.Contains(t, result, "baidu.com", "google.com")

	result = parser.ExtractAffectedDomains([]string{"www.baidu.com", "*.baidu.com"})
	assert.Equal(t, 1, len(result))
	assert.Contains(t, result, "baidu.com")

	result = parser.ExtractAffectedDomains([]string{"video.baidu.com", "*.baidu.com", "mail.baidu.com"})
	assert.Equal(t, 3, len(result))
	assert.Contains(t, result, "baidu.com")
	assert.Contains(t, result, "video.baidu.com")
	assert.Contains(t, result, "mail.baidu.com")

	result = parser.ExtractAffectedDomains([]string{"video.baidu.com", "*.baidu.com", "mail.baidu.com", "book.baidu.com", "func.baidu.com"})
	assert.Equal(t, 1, len(result))
	assert.Contains(t, result, "baidu.com")

	result = parser.ExtractAffectedDomains([]string{"video.baidu.com", "*.baidu.com", "mail.baidu.com", "book.baidu.com", "func.baidu.com", "video.google.com", "mail.google.com", "book.mail.google.com"})
	assert.Equal(t, 2, len(result))
	assert.Contains(t, result, "baidu.com", "google.com")
}

func TestParseDomainName(t *testing.T) {
	parser, err := NewDomainParser()
	require.NoError(t, err)

	result, err := parser.ParseDomainName("www.baidu.com")
	require.NoError(t, err)
	assert.Equal(t, 1, len(result))

	result, err = parser.ParseDomainName("*.*.baidu.com")
	require.Error(t, err)

	result, err = parser.ParseDomainName("_hi.baidu.com")
	require.Error(t, err)

	result, err = parser.ParseDomainName("video.mail.baidu.com")
	require.NoError(t, err)
	assert.Equal(t, 3, len(result))
	assert.Contains(t, result, "video.mail.baidu.com", "mail.baidu.com", "baidu.com")
}
