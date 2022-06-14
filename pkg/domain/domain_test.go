package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIsValidDomain: test strange domain names
func TestIsValidDomain(t *testing.T) {
	tests := map[string]bool{
		".com":                        false,
		"com":                         false,
		"net":                         false,
		".baidu.com":                  false,
		"_www.baidu.com":              false,
		"*.*.baidu.com":               false,
		"device-a6789012.baidu.com":   true,
		"www.baidu.com":               true,
		"www.google.com":              true,
		"bqiwodnqwpdq.www.google.com": true,
		"www.2017.cuni.cz":            true,
		"150.tum.de":                  true,
		"601602.com":                  true,
		"*.9292.nl":                   true,
		// "dnn_maps.carlisle.gov.uk":    true, // valid DNS entry
		// "räksmörgås.josefsson.org":    true, // IDN domain
		// "日本語.idn.icann.org":           true, // IDN domain
	}

	for k, v := range tests {
		t.Run(k, func(t *testing.T) {
			k, v := k, v
			t.Parallel()
			assert.Equal(t, v, IsValidDomain(k))
		})
	}
}

// TestUniqueValidDomainName: test uniqueValidDomainName()
func TestUniqueValidDomainName(t *testing.T) {
	test := map[string]struct {
		input  []string
		length int
	}{
		"1": {
			input:  []string{"www.baidu.com", "www.baidu.com"},
			length: 1,
		},
		"2": {
			input:  []string{"*.baidu.com", "www.baidu.com", "baidu.com"},
			length: 1,
		},
		"3": {
			input:  []string{"com", "*.*.baidu.com", "12378.com"},
			length: 0,
		},
		"4": {
			input:  []string{"video.google.com", "mail.google.com", "audio.google.com"},
			length: 3,
		},
	}

	for name, v := range test {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, v.length, len(uniqueValidDomainName(v.input)))
		})
	}
}

// TestSplitE2LD: test SplitE2LD()
func TestSplitE2LD(t *testing.T) {
	test := map[string]struct {
		input  string
		output []string
		length int
	}{
		"1": {
			input:  "baidu.com",
			output: []string{"baidu.com"},
			length: 1,
		},

		"2": {
			input:  "video.www.baidu.com",
			output: []string{"baidu.com", "www", "video"},
			length: 3,
		},

		"3": {
			input:  "video.baidu.com",
			output: []string{"baidu.com", "video"},
			length: 2,
		},
	}

	for name, v := range test {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			result, err := SplitE2LD(v.input)
			assert.NoError(t, err)
			assert.Equal(t, v.length, len(result))
			for _, outputString := range v.output {
				assert.Contains(t, result, outputString)
			}
		})
	}
}

// TestFindLongestSuffix: test findLongestSuffix()
func TestFindLongestSuffix(t *testing.T) {
	test := map[string]struct {
		input  [][]string
		output string
	}{
		"1": {
			input:  [][]string{{"mail", "video"}, {"audio", "video"}},
			output: "video.",
		},
		"2": {
			input:  [][]string{{"tv", "mail", "video"}, {"mail", "video"}, {"mail", "video"}},
			output: "mail.video.",
		},
		"3": {
			input:  [][]string{{"tv", "mail", "mail"}, {"mail", "mail"}, {"mail", "video"}},
			output: "",
		},
	}

	for name, v := range test {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, v.output, findLongestSuffix(v.input))
		})
	}
}

// TestExtractAffectedDomains: test ExtractAffectedDomains()
func TestExtractAffectedDomains(t *testing.T) {
	test := map[string]struct {
		input  []string
		output []string
	}{
		"1": {
			input:  []string{"www.baidu.com", "www.google.com"},
			output: []string{"baidu.com", "google.com"},
		},
		"2": {
			input:  []string{"www.baidu.com", "*.baidu.com"},
			output: []string{"baidu.com"},
		},
		"3": {
			input:  []string{"video.baidu.com", "*.baidu.com", "mail.baidu.com"},
			output: []string{"baidu.com", "video.baidu.com", "mail.baidu.com"},
		},
		"4": {
			input:  []string{"video.baidu.com", "*.baidu.com", "mail.baidu.com", "book.baidu.com", "func.baidu.com"},
			output: []string{"baidu.com"},
		},
		"5": {
			input: []string{"video.baidu.com", "*.baidu.com", "mail.baidu.com", "book.baidu.com",
				"func.baidu.com", "video.google.com", "mail.google.com", "book.mail.google.com"},
			output: []string{"baidu.com", "google.com"},
		},
	}

	for name, v := range test {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			result := ExtractAffectedDomains(v.input)
			assert.Equal(t, len(v.output), len(result))
			for _, outputString := range v.output {
				assert.Contains(t, result, outputString)
			}
		})
	}
}

// TestParseDomainName: test ParseDomainName()
func TestParseDomainName(t *testing.T) {
	noErr := map[string]struct {
		input  string
		length int
		output []string
	}{
		"1": {
			input:  "www.baidu.com",
			length: 1,
			output: []string{"baidu.com"},
		},
		"2": {
			input:  "video.mail.baidu.com",
			length: 3,
			output: []string{"video.mail.baidu.com", "mail.baidu.com", "baidu.com"},
		},
	}

	hasErr := map[string]struct {
		input string
	}{
		"1": {
			input: "*.*.baidu.com",
		},
		"2": {
			input: "_hi.baidu.com",
		},
	}

	for name, v := range noErr {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			result, err := ParseDomainName(v.input)
			require.NoError(t, err)
			assert.Equal(t, v.length, len(result))
			for _, outputString := range v.output {
				assert.Contains(t, result, outputString)
			}
		})
	}

	for name, v := range hasErr {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseDomainName(v.input)
			require.Error(t, err)
		})
	}
}
