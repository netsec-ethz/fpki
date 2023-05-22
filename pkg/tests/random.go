package tests

import (
	"math/rand"
	"time"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"

	"github.com/netsec-ethz/fpki/pkg/util"
	"github.com/stretchr/testify/require"
)

func RandomBytesForTest(t require.TestingT, size int) []byte {
	buff := make([]byte, size)
	n, err := rand.Read(buff)
	require.NoError(t, err)
	require.Equal(t, size, n)
	return buff
}

func RandomX509Cert(t require.TestingT, domain string) *ctx509.Certificate {
	return &ctx509.Certificate{
		DNSNames: []string{domain},
		Subject: pkix.Name{
			CommonName: domain,
		},
		NotBefore: util.TimeFromSecs(0),
		NotAfter:  time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC),
		Raw:       RandomBytesForTest(t, 10),
	}
}
