package util

import (
	ctx509 "github.com/google/certificate-transparency-go/x509"
)

// ExtractCertDomains: get domain from cert: {Common Name, SANs}
func ExtractCertDomains(cert *ctx509.Certificate) []string {
	domains := make(map[string]struct{})
	if len(cert.Subject.CommonName) != 0 {
		domains[cert.Subject.CommonName] = struct{}{}
	}

	for _, dnsName := range cert.DNSNames {
		domains[dnsName] = struct{}{}
	}

	result := []string{}
	for k := range domains {
		result = append(result, k)
	}
	return result
}
