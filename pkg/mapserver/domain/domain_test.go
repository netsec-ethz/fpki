package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

//TestEffectedDomains: test the func of ExtractEffectedDomains()
func Test_AffectedDomains(t *testing.T) {

	result := ExtractAffectedDomains([]string{"a.b.com", "b.com", "c.net", "a.b.c.net", "1.a.b.com", "a.apple"})
	assert.Equal(t, 3, len(result), "length error")
	assert.Equal(t, true, stringIsContained("b.com", result), "output error")
	assert.Equal(t, true, stringIsContained("c.net", result), "output error")
	assert.Equal(t, true, stringIsContained("a.apple", result), "output error")

	result = ExtractAffectedDomains([]string{"a.b.com"})
	assert.Equal(t, 1, len(result), "length error")
	assert.Equal(t, true, stringIsContained("a.b.com", result), "output error")

	result = ExtractAffectedDomains([]string{"a.c.s.f.c.a.b.com", "c.s.f.c.a.b.com"})
	assert.Equal(t, true, stringIsContained("c.s.f.c.a.b.com", result), "output error")

	result = ExtractAffectedDomains([]string{"a.c.s.f.c.a.b.com", "c.s.f.c.a.b.com", "f.g.te.c.sa.net", "te.c.sa.net", "a.sd.q.wqe.f.g.te.c.sa.net"})
	assert.Equal(t, true, stringIsContained("c.s.f.c.a.b.com", result), "output error")
	assert.Equal(t, true, stringIsContained("te.c.sa.net", result), "output error")

	result = ExtractAffectedDomains([]string{"a.b.com", "a.a.b.com"})
	assert.Equal(t, 1, len(result), "length error")
	assert.Equal(t, true, stringIsContained("a.b.com", result), "output error")

	//  privately maintained TLD
	result = ExtractAffectedDomains([]string{"abc.kasserver.com", "hhn.kasserver.com"})
	assert.Equal(t, 2, len(result), "length error")
	assert.Equal(t, true, stringIsContained("abc.kasserver.com", result), "output error")
	assert.Equal(t, true, stringIsContained("hhn.kasserver.com", result), "output error")

	// strange domain name
	result = ExtractAffectedDomains([]string{".baidu.com"})
	assert.Equal(t, 0, len(result), "length error")

	// wild card certs
	result = ExtractAffectedDomains([]string{"*.baidu.com"})
	assert.Equal(t, 1, len(result), "length error")
	assert.Equal(t, true, stringIsContained("baidu.com", result), "output error")

	// wild card certs
	result = ExtractAffectedDomains([]string{"*.baidu.com", "hotmail.baidu.com", "video.chat.baidu.com"})
	assert.Equal(t, 1, len(result), "length error")
	assert.Equal(t, true, stringIsContained("baidu.com", result), "output error")

	// strange url
	result = ExtractAffectedDomains([]string{"*.baidu.com", "hotmail,baidu.com", "video.chat.baidu.com"})
	assert.Equal(t, 2, len(result), "length error")
	assert.Equal(t, true, stringIsContained("baidu.com", result), "output error")
	assert.Equal(t, true, stringIsContained("hotmail,baidu.com", result), "output error")

	// strange url
	result = ExtractAffectedDomains([]string{"hotmail,baidu.com", "hihihi.hotmail,baidu.com"})
	assert.Equal(t, 1, len(result), "length error")
	assert.Equal(t, true, stringIsContained("hotmail,baidu.com", result), "output error")

	// strange url
	result = ExtractAffectedDomains([]string{"h#$^%@@,baidu.com", "hihihi.h#$^%@@,baidu.com"})
	assert.Equal(t, 1, len(result), "length error")
	assert.Equal(t, true, stringIsContained("h#$^%@@,baidu.com", result), "output error")

	// public suffix should not be parsed
	result = ExtractAffectedDomains([]string{".com"})
	assert.Equal(t, 0, len(result), "length error")

	// public suffix should not be parsed
	result = ExtractAffectedDomains([]string{"co.uk"})
	assert.Equal(t, 0, len(result), "length error")
}

// TestfindLongestMatch: test for findLongestMatch
func Test_findLongestMatch(t *testing.T) {
	result := findLongestMatch([][]string{{"a", "b"}, {"c", "b"}})
	assert.Equal(t, "b.", result, "findLongestMatch error")

	result = findLongestMatch([][]string{{"a", "b", "a"}, {"c", "b"}})
	assert.Equal(t, "", result, "findLongestMatch error")

	result = findLongestMatch([][]string{{"a", "b", "f"}, {"c", "b", "f"}})
	assert.Equal(t, "b.f.", result, "findLongestMatch error")

	result = findLongestMatch([][]string{{"a", "123", "b", "f"}, {"c", "123", "b", "f"}})
	assert.Equal(t, "123.b.f.", result, "findLongestMatch error")
}

func stringIsContained(target string, stringSet []string) bool {
	for _, v := range stringSet {
		if target == v {
			return true
		}
	}
	return false
}
