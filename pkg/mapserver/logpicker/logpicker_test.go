package logpicker

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEffectedDomains(t *testing.T) {

	result := ExtractEffectedDomains([]string{"a.b.com", "b.com", "c.net", "a.b.c.net", "1.a.b.com", "a.apple"})
	assert.Equal(t, 3, len(result), "length error")
	assert.Equal(t, true, stringIsContained("b.com", result), "output error")
	assert.Equal(t, true, stringIsContained("c.net", result), "output error")
	assert.Equal(t, true, stringIsContained("a.apple", result), "output error")

	result = ExtractEffectedDomains([]string{"a.b.com"})
	assert.Equal(t, 1, len(result), "length error")
	assert.Equal(t, true, stringIsContained("a.b.com", result), "output error")

	result = ExtractEffectedDomains([]string{"a.c.s.f.c.a.b.com", "c.s.f.c.a.b.com"})
	assert.Equal(t, true, stringIsContained("c.s.f.c.a.b.com", result), "output error")

	result = ExtractEffectedDomains([]string{"a.c.s.f.c.a.b.com", "c.s.f.c.a.b.com", "f.g.te.c.sa.net", "te.c.sa.net", "a.sd.q.wqe.f.g.te.c.sa.net"})
	assert.Equal(t, true, stringIsContained("c.s.f.c.a.b.com", result), "output error")
	assert.Equal(t, true, stringIsContained("te.c.sa.net", result), "output error")

	result = ExtractEffectedDomains([]string{"a.b.com", "a.a.b.com"})
	assert.Equal(t, 1, len(result), "length error")
	assert.Equal(t, true, stringIsContained("a.b.com", result), "output error")

	//  privately maintained TLD
	result = ExtractEffectedDomains([]string{"abc.kasserver.com", "hhn.kasserver.com"})
	assert.Equal(t, 2, len(result), "length error")
	assert.Equal(t, true, stringIsContained("abc.kasserver.com", result), "output error")
	assert.Equal(t, true, stringIsContained("hhn.kasserver.com", result), "output error")

	// strange domain name
	result = ExtractEffectedDomains([]string{".baidu.com"})
	assert.Equal(t, 0, len(result), "length error")

	// wild card certs
	result = ExtractEffectedDomains([]string{"*.baidu.com"})
	assert.Equal(t, 1, len(result), "length error")
	assert.Equal(t, true, stringIsContained("baidu.com", result), "output error")

	// wild card certs
	result = ExtractEffectedDomains([]string{"*.baidu.com", "hotmail.baidu.com", "video.chat.baidu.com"})
	assert.Equal(t, 1, len(result), "length error")
	assert.Equal(t, true, stringIsContained("baidu.com", result), "output error")

	// strange url
	result = ExtractEffectedDomains([]string{"*.baidu.com", "hotmail,baidu.com", "video.chat.baidu.com"})
	assert.Equal(t, 2, len(result), "length error")
	assert.Equal(t, true, stringIsContained("baidu.com", result), "output error")
	assert.Equal(t, true, stringIsContained("hotmail,baidu.com", result), "output error")

	// strange url
	result = ExtractEffectedDomains([]string{"hotmail,baidu.com", "hihihi.hotmail,baidu.com"})
	assert.Equal(t, 1, len(result), "length error")
	assert.Equal(t, true, stringIsContained("hotmail,baidu.com", result), "output error")

	// strange url
	result = ExtractEffectedDomains([]string{"h#$^%@@,baidu.com", "hihihi.h#$^%@@,baidu.com"})
	assert.Equal(t, 1, len(result), "length error")
	assert.Equal(t, true, stringIsContained("h#$^%@@,baidu.com", result), "output error")

	// public suffix should not be parsed
	result = ExtractEffectedDomains([]string{".com"})
	assert.Equal(t, 0, len(result), "length error")

	// public suffix should not be parsed
	result = ExtractEffectedDomains([]string{"co.uk"})
	assert.Equal(t, 0, len(result), "length error")
}

func stringIsContained(target string, stringSet []string) bool {
	for _, v := range stringSet {
		if target == v {
			return true
		}
	}
	return false
}
