package util

import (
	"time"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
)

// ExtractNames returns a list of lists of names. Since each certificate contains several names,
// the function returns a collection of slices of names, extracted from each certificate's SAN.
func ExtractNames(certs []*ctx509.Certificate) [][]string {
	names := make([][]string, len(certs))
	for i, c := range certs {
		names[i] = updater.ExtractCertDomains(c)
	}
	return names
}

// ExtractExpirations simply returns all expiration times in order.
func ExtractExpirations(certs []*ctx509.Certificate) []*time.Time {
	expirations := make([]*time.Time, len(certs))
	for i, c := range certs {
		expirations[i] = &c.NotAfter
	}
	return expirations
}
