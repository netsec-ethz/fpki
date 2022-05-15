package logpicker

import (
	"fmt"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// This go file includes the func for domain-related funcs
// Motivation for this go file is to minimise the number of modifications of the domain entries in the db.
// Some certificates have a large number of SANs, some even have 100 (maximum number of SANs for certificates) SAN.
// But most of the SANs have a common prefix.

// Example:
//     common name:   example.com
//     SANs: a.example.com email.example.com hotmail.example.com pki.example.com chat.example.com video.example.com ...

// So in this case, it's not efficient to update the certificate for all the SANs.
// So, we will find the longest common prefix (must be longer than E2LD) among all the SANs and common name

//  Example:
//     common name:   example.com
//     SANs: a.example.com email.example.com hotmail.example.com pki.example.com chat.example.com video.example.com ...
// Output: Effectived domain: example.com

//  Example:
//     common name:   example.com
//     SANs: a.example.com email.example.com hotmail.example.com b.helloworld.com hotmail.helloworld.com
// Output: Effectived domain: example.com, helloworld.com

// extract the effected domain, given a list of domain name (common name + SANs)
func extractEffectedDomains(domainNames []string) []string {
	result := make(map[string][][]string)
	for _, domainName := range domainNames {
		// split the domain name into: E2LD + child domains
		dividedName, err := splitE2LD(domainName)
		if err != nil {
			// print the error (for debugging), and skip this domain.
			fmt.Println(err)
			continue
		}
		prefix := dividedName[:len(dividedName)-1]
		e2ld := dividedName[len(dividedName)-1]
		// append the remaining domain name (minus E2LD) to the map for further processing, grouped by same E2LD
		result[e2ld] = append(result[e2ld], prefix)
	}

	effectedDomains := []string{}
	for k, v := range result {
		// find the longest match of a list of domain names.
		newDomain := findLongestMatch(v) + k
		effectedDomains = append(effectedDomains, newDomain)
	}
	return effectedDomains
}

// find longest match
func findLongestMatch(domainNames [][]string) string {
	result := ""
	// shorest length of all the strings
	shortestLength := findShortestLength(domainNames)

main_loop:
	// loop to compare the domain name one level by one level
	for i := 0; i < shortestLength; i++ {
		newName := domainNames[0][shortestLength-1-i]
		for _, name := range domainNames {
			// if one level of domain name is not equal among all the input
			if name[shortestLength-1-i] != newName {
				break main_loop
			}
			newName = name[shortestLength-1-i]
		}
		result = newName + "." + result
	}
	return result
}

func findShortestLength(domainNames [][]string) int {
	length := len(domainNames[0])
	for _, name := range domainNames {
		if len(name) < length {
			length = len(name)
		}
	}
	return length
}

func splitE2LD(domain string) ([]string, error) {
	// remove wildcard
	if len(domain) > 2 && domain[:2] == "*." {
		domain = domain[2:]
	}

	// remove "www."
	if len(domain) > 4 && domain[:4] == "www." {
		domain = domain[4:]
	}

	// check if the domain name has public suffix
	_, icann := publicsuffix.PublicSuffix(domain)
	// if the suffix is not publicly maintained, directly return the domain name
	if !icann {
		return []string{domain}, nil
	}

	// try to get E2LD
	e2LD, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return nil, fmt.Errorf("couldn't extract e2LD of '%s': %s", domain, err)
	}

	domain = strings.TrimSuffix(domain, e2LD)
	domain = strings.TrimSuffix(domain, ".")
	var subdomains []string
	if domain != "" {
		subdomains = strings.Split(domain, ".")
	}
	subdomains = append(subdomains, e2LD)

	return subdomains, nil
}
