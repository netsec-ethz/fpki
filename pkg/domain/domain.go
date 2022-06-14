package domain

import (
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// This go file includes the func for domain-related funcs
// Motivation for this go file is to minimize the number of modifications of the domain entries in the db.
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
// Output: Effective domain: example.com

//  Example:
//     common name:   example.com
//     SANs: a.example.com email.example.com hotmail.example.com b.helloworld.com hotmail.helloworld.com
// Output: Effective domain: example.com, helloworld.com

const (
	MaxDomainLength = 255
	MaxSANLength    = 4
)

// InvalidDomainNameErr: thrown when the domain name is not valid
var InvalidDomainNameErr = fmt.Errorf("Invalid Domain Name")

var empty struct{}

// DomainParser: regular expression to filter the domain name
type DomainParser struct {
	wildcardDomain *regexp.Regexp
	viableDomain   *regexp.Regexp
	correctLabel   *regexp.Regexp
}

// NewDomainParser: return a new domain parser to parse the domain
func NewDomainParser() (*DomainParser, error) {
	var err error
	wildcardDomain, err := regexp.Compile("^\\*\\..*$")
	if err != nil {
		return nil, fmt.Errorf("NewDomainParser | wildcardDomain | %w", err)
	}
	viableDomain, err := regexp.Compile("^(\\*\\.)?[^*]*$")
	if err != nil {
		return nil, fmt.Errorf("NewDomainParser | viableDomain | %w", err)
	}

	correctLabel, err := regexp.Compile("^(\\*|[[:alnum:]]|[[:alnum:]][[:alnum:]-]{0,61}[[:alnum:]])$")
	if err != nil {
		return nil, fmt.Errorf("NewDomainParser | correctLabel | %w", err)
	}

	return &DomainParser{
		wildcardDomain: wildcardDomain,
		viableDomain:   viableDomain,
		correctLabel:   correctLabel,
	}, nil
}

// ExtractAffectedDomains: extract the affected domain, given a list of domain name (common name + SANs)
func (parser *DomainParser) ExtractAffectedDomains(domainNames []string) []string {
	uniqueNames := parser.uniqueValidDomainName(domainNames)

	// if number of SANs is not too large, we do not divide the domains
	if len(uniqueNames) <= MaxSANLength {
		return uniqueNames
	}

	// get E2LD and prefix of each domain name
	// eg. mail.video.google.com -> map["google.com"] : {{"mail", "video"}}
	//     audio.video.google.com -> map["google.com"] : {{"mail", "video"}, {"audio", "video"}}
	result := make(map[string][][]string)
	for _, domainName := range uniqueNames {
		// split the domain name into: E2LD + child domains
		dividedName, err := SplitE2LD(domainName)
		if err != nil {
			// TODO(yongzhe): print the error (for debugging), and skip this domain.
			fmt.Println(err)
			continue
		}
		prefix := dividedName[:len(dividedName)-1]
		e2ld := dividedName[len(dividedName)-1]
		// append the remaining domain name (minus E2LD) to the map for further processing, grouped by same E2LD
		result[e2ld] = append(result[e2ld], prefix)
	}

	affectedDomains := make([]string, 0, len(result))
	for k, v := range result {
		// find the longest match of a list of domain names.
		newDomain := findLongestSuffix(v) + k
		affectedDomains = append(affectedDomains, newDomain)
	}
	return affectedDomains
}

// IsValidDomain: check if this domain is a valid domain
func (parser *DomainParser) IsValidDomain(domain string) bool {
	// removes domains with wildcard labels other than the first label
	if !parser.viableDomain.Match([]byte(domain)) {
		return false
	}
	// max length for a domain
	if len(domain) > MaxDomainLength {
		return false
	}

	suffix, iccan := publicsuffix.PublicSuffix(domain)
	// if this is a TLD, return false
	if iccan && suffix == domain {
		return false
	}

	for _, n := range strings.Split(domain, ".") {
		// remove invalid characters and hyphens at the beginning and end
		if !parser.correctLabel.Match([]byte(n)) {
			return false
		}
	}
	return true
}

// SplitE2LD: return the E2LD and the rest of the domain names
func SplitE2LD(domain string) ([]string, error) {
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

// removeWildCardAndWWW: remove www. and *.
func removeWildCardAndWWW(domainName string) string {
	// remove "*."
	if len(domainName) > 2 && domainName[:2] == "*." {
		domainName = domainName[2:]
	}

	// remove "www."
	if len(domainName) > 4 && domainName[:4] == "www." {
		domainName = domainName[4:]
	}

	return domainName
}

// uniqueValidDomainName: extract valid domain names
func (parser *DomainParser) uniqueValidDomainName(domainNames []string) []string {
	uniqueDomainName := make(map[string]struct{})
	for _, domainName := range domainNames {
		if !parser.IsValidDomain(domainName) {
			fmt.Printf("    !!! invalid domain name: \"%s\"\n", domainName)
			continue
		}
		name := removeWildCardAndWWW(domainName)
		uniqueDomainName[name] = empty
	}
	result := make([]string, 0, len(uniqueDomainName))
	for k := range uniqueDomainName {
		result = append(result, k)
	}
	return result
}

// findLongestSuffix: find longest match
func findLongestSuffix(domainNames [][]string) string {
	result := ""
	// shortest length of all the strings
	shortestLength := findShortestLength(domainNames)

	// loop to compare the domain name one level by one level
	for i := 0; i < shortestLength; i++ {
		newName := domainNames[0][len(domainNames[0])-1-i]
		for _, name := range domainNames {
			// if one level of domain name is not equal among all the input
			if name[len(name)-1-i] != newName {
				return result
			}
			newName = name[len(name)-1-i]
		}
		result = newName + "." + result
	}
	return result
}

// findShortestLength: find shorest length of a list of splited domains
func findShortestLength(domainNames [][]string) int {
	length := len(domainNames[0])
	for _, name := range domainNames {
		if len(name) < length {
			length = len(name)
		}
	}
	return length
}

// ParseDomainName: get the parent domain until E2LD, return a list of domains(remove the www. and *.)
// eg: video.google.com -> video.google.com google.com
// eg: *.google.com -> google.com
// eg: www.google.com -> google.com
func (parser *DomainParser) ParseDomainName(domainName string) ([]string, error) {
	if !parser.IsValidDomain(domainName) {
		return nil, InvalidDomainNameErr
	}

	domainName = removeWildCardAndWWW(domainName)

	result, err := SplitE2LD(domainName)
	resultString := []string{}
	var domain string
	if err != nil {
		return nil, fmt.Errorf("parseDomainName | SplitE2LD | %w", err)
	} else if len(result) == 0 {
		return nil, fmt.Errorf("domain length is zero")
	}
	domain = result[len(result)-1]
	resultString = append(resultString, domain)
	for i := len(result) - 2; i >= 0; i-- {
		domain = result[i] + "." + domain
		resultString = append(resultString, domain)
	}
	return resultString, nil
}
