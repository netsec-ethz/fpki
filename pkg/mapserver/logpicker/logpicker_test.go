package logpicker

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEffectedDomains(t *testing.T) {
	result := extractEffectedDomains([]string{"a.b.com", "b.com", "c.net", "a.b.c.net", "1.a.b.com", "a.apple"})
	assert.Equal(t, 3, len(result), "length error")
	fmt.Println(result)

	result = extractEffectedDomains([]string{"a.b.com"})
	assert.Equal(t, 1, len(result), "length error")
	fmt.Println(result)

	result = extractEffectedDomains([]string{"c.a.b.com"})
	assert.Equal(t, "c.a.b.com", result[0], "length error")
	fmt.Println(result)

	result = extractEffectedDomains([]string{"a.b.com", "a.a.b.com"})
	assert.Equal(t, "a.b.com", result[0], "length error")
	fmt.Println(result)

	result = extractEffectedDomains([]string{"abc.kasserver.com", "hhn.kasserver.com"})
	fmt.Println(result)

	result = extractEffectedDomains([]string{"com"})
	fmt.Println(result)

	result = extractEffectedDomains([]string{"co.uk"})
	fmt.Println(result)
}
